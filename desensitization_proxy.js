class DesensitizationProxy {
    constructor() {
        this.mapping = {};
        this.reverseMapping = {};
        this.counters = {
            phone: 0,
            idcard: 0,
            bank: 0,
            amount: 0,
            company: 0,
            name: 0,
            email: 0,
            wechat: 0,
            custom: 0
        };
        this.logs = [];
        this.settings = {
            enabled: true,
            encryptionKey: 'desensitization_proxy_key',
            maxLogSize: 100,
            maskStyle: 'placeholder',
            customRules: []
        };
        this.patterns = [];
        this.loadDefaultPatterns();
    }

    loadDefaultPatterns() {
        this.patterns = [
            { category: 'phone', pattern: /1[3-9]\d{9}/g, placeholder: 'PH' },
            { category: 'idcard', pattern: /\d{17}[\dXx]/g, placeholder: 'ID' },
            { category: 'bankcard', pattern: /(62[0-9]{14,17}|4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})/g, placeholder: 'BN' },
            { category: 'email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, placeholder: 'EM' },
            { category: 'amount', pattern: /(¥|￥)?(\d{1,3}(,\d{3})*(\.\d{2})?)\s*元/g, placeholder: 'AM' },
            { category: 'company', pattern: /([\u4e00-\u9fa5]{2,8})(集团|公司|有限公司|股份|控股|有限责任)/g, placeholder: 'CP' },
            { category: 'name', pattern: /\b([\u4e00-\u9fa5]{2,3})(先生|女士|经理|总)\b/g, placeholder: 'NM' },
            { category: 'wechat', pattern: /(微信号|微信|WeChat|wechat)\s*[:：]?\s*([a-zA-Z0-9_-]{5,})/g, placeholder: 'WC' },
            { category: 'ip', pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, placeholder: 'IP' },
            { category: 'url', pattern: /https?:\/\/[\w\-._~:/?#@!$&'()*+,;=%\\[\]]+/g, placeholder: 'URL' },
            { category: 'password', pattern: /(password|密码|passwd|pwd)[\s:=]*[a-zA-Z0-9]{6,}/gi, placeholder: 'PW' },
            { category: 'account', pattern: /(账号|用户名|user|username|login)[\s:=]*[a-zA-Z0-9_]{3,}/gi, placeholder: 'AC' }
        ];
    }

    loadConfig(config) {
        if (!config) return;
        if (config.regex_patterns) {
            config.regex_patterns.forEach(item => {
                const existing = this.patterns.find(p => p.category === item.category);
                if (existing) {
                    existing.pattern = new RegExp(item.pattern, 'g');
                } else {
                    this.patterns.push({
                        category: item.category,
                        pattern: new RegExp(item.pattern, 'g'),
                        placeholder: item.category.toUpperCase().substring(0, 2)
                    });
                }
            });
        }
        if (config.keywords) {
            Object.keys(config.keywords).forEach(category => {
                config.keywords[category].forEach(keyword => {
                    this.addCustomRule(category, keyword, category.toUpperCase().substring(0, 2));
                });
            });
        }
    }

    reset() {
        this.mapping = {};
        this.reverseMapping = {};
        this.counters = {
            phone: 0, idcard: 0, bank: 0, amount: 0,
            company: 0, name: 0, email: 0, wechat: 0, custom: 0
        };
    }

    setSettings(newSettings) {
        this.settings = { ...this.settings, ...newSettings };
    }

    getSettings() {
        return { ...this.settings };
    }

    escapeRegExp(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    generateCode(category, originalValue) {
        const prefix = category.toUpperCase().substring(0, 2);
        const length = 8;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let code;
        do {
            code = prefix + Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        } while (code in this.reverseMapping);
        return code;
    }

    desensitize(text) {
        if (!this.settings.enabled || !text) return text;

        this.reset();
        const originalLength = text.length;
        let result = String(text);

        const sources = this.patterns.map(p => p.pattern.source);
        const combinedPattern = new RegExp(sources.join('|'), 'g');
        const processed = new Set();

        const matches = result.match(combinedPattern) || [];
        matches.forEach(matchedStr => {
            if (processed.has(matchedStr)) return;
            processed.add(matchedStr);

            let category = 'custom';
            for (const p of this.patterns) {
                const testRegex = new RegExp(p.pattern.source);
                if (testRegex.test(matchedStr)) {
                    category = p.category;
                    break;
                }
            }
            const code = this.generateCode(category, matchedStr);
            this.mapping[matchedStr] = code;
            this.reverseMapping[code] = matchedStr;
            this.counters[category] = (this.counters[category] || 0) + 1;
        });

        if (this.settings.customRules && this.settings.customRules.length > 0) {
            this.settings.customRules.forEach(rule => {
                let customPattern;
                try {
                    customPattern = rule.pattern instanceof RegExp
                        ? new RegExp(rule.pattern.source, 'g')
                        : new RegExp(rule.pattern, 'g');
                } catch (e) {
                    return;
                }
                const customMatches = result.match(customPattern) || [];
                customMatches.forEach(matchedStr => {
                    if (processed.has(matchedStr)) return;
                    processed.add(matchedStr);

                    const code = this.generateCode('custom', matchedStr);
                    this.mapping[matchedStr] = code;
                    this.reverseMapping[code] = matchedStr;
                    this.counters.custom++;
                });
            });
        }

        const sortedCodes = Object.keys(this.mapping).sort((a, b) => b.length - a.length);
        const regexStr = sortedCodes.map(s => this.escapeRegExp(s)).join('|');
        if (regexStr) {
            const replaceRegex = new RegExp(regexStr, 'g');
            result = result.replace(replaceRegex, (matched) => this.mapping[matched]);
        }

        this.addLog('desensitize', '数据脱敏完成', {
            originalLength: originalLength,
            replacedCount: processed.size
        });

        return result;
    }

    restore(text) {
        if (!this.settings.enabled || !text) return text;
        
        let result = String(text);
        
        const sortedCodes = Object.keys(this.reverseMapping).sort((a, b) => b.length - a.length);
        const regexStr = sortedCodes.map(s => this.escapeRegExp(s)).join('|');
        if (regexStr) {
            const replaceRegex = new RegExp(regexStr, 'g');
            result = result.replace(replaceRegex, (matched) => this.reverseMapping[matched]);
        }

        this.addLog('restore', '数据还原完成', {
            restoredCount: Object.keys(this.reverseMapping).length
        });

        return result;
    }

    restoreWithKey(text, keyMapping) {
        if (!text || !keyMapping || typeof keyMapping !== 'object') return text;
        
        let result = String(text);
        
        const sortedCodes = Object.keys(keyMapping).sort((a, b) => b.length - a.length);
        const regexStr = sortedCodes.map(s => this.escapeRegExp(s)).join('|');
        if (regexStr) {
            const replaceRegex = new RegExp(regexStr, 'g');
            result = result.replace(replaceRegex, (matched) => keyMapping[matched] || matched);
        }

        this.addLog('restoreWithKey', '使用密钥文件还原数据完成', {
            restoredCount: Object.keys(keyMapping).length
        });

        return result;
    }

    addLog(type, message, data) {
        this.logs.unshift({
            timestamp: Date.now(),
            type: type,
            message: message,
            data: data
        });
        if (this.logs.length > this.settings.maxLogSize) {
            this.logs.pop();
        }
    }

    getLogs() {
        return [...this.logs];
    }

    clearLogs() {
        this.logs = [];
    }

    addCustomRule(name, pattern, placeholderPrefix) {
        this.settings.customRules[name] = {
            pattern: new RegExp(pattern, 'g'),
            placeholderPrefix: placeholderPrefix || 'CU'
        };
    }

    removeCustomRule(name) {
        delete this.settings.customRules[name];
    }

    getMapping() {
        return JSON.parse(JSON.stringify(this.mapping));
    }

    setMapping(mapping) {
        this.mapping = JSON.parse(JSON.stringify(mapping));
        this.reverseMapping = {};
        Object.keys(this.mapping).forEach(key => {
            this.reverseMapping[this.mapping[key]] = key;
        });
    }

    getStatistics() {
        const totalCount = Object.values(this.counters).reduce((a, b) => a + b, 0);
        return {
            totalReplaced: totalCount,
            byCategory: { ...this.counters },
            logsCount: this.logs.length,
            mappingSize: Object.keys(this.mapping).length
        };
    }

    exportLogs() {
        const dataStr = JSON.stringify(this.logs, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'desensitization_logs_' + new Date().toISOString().split('T')[0] + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    validateMapping() {
        let valid = true;
        const errors = [];
        Object.keys(this.mapping).forEach(key => {
            if (!/^\[[A-Z]{2}\d+\]$/.test(key)) {
                valid = false;
                errors.push('无效的占位符格式: ' + key);
            }
            if (!this.mapping[key] || typeof this.mapping[key] !== 'string') {
                valid = false;
                errors.push('无效的映射值: ' + key);
            }
        });
        return { valid, errors };
    }
}

const desensitizationProxy = new DesensitizationProxy();

class PrivacyDetector {
    constructor() {
        this.enabled = true;
        this.maxDetectionLength = 10000;
        this.stats = {
            totalDetections: 0,
            highRiskDetections: 0,
            mediumRiskDetections: 0,
            lastDetectionTime: null,
            lastDetectedPatterns: []
        };
        this.patterns = [];
        this.loadDefaultPatterns();
    }

    loadDefaultPatterns() {
        this.patterns = [
            { name: '机密标记', pattern: /(机密|绝密|保密|内部资料|内部文件|内部信息)/gi, severity: 'high' },
            { name: '商业秘密', pattern: /(商业秘密|商业机密|知识产权|专利|技术秘密)/gi, severity: 'high' },
            { name: '合同敏感信息', pattern: /(合同编号|合同金额|合同条款|协议金额|保密协议|竞业限制)/gi, severity: 'high' },
            { name: '客户信息', pattern: /(客户名单|客户资料|客户信息|客户联系方式|客户电话)/gi, severity: 'high' },
            { name: '财务敏感数据', pattern: /(财务报表|财务数据|审计报告|纳税申报|发票号码|银行账户|银行账号)/gi, severity: 'high' },
            { name: '报价信息', pattern: /(报价单|报价金额|投标报价|底价|成本价)/gi, severity: 'high' },
            { name: '员工信息', pattern: /(员工名单|薪资|工资|薪酬|年终奖|绩效奖金)/gi, severity: 'medium' },
            { name: '项目机密', pattern: /(项目计划|项目进度|项目预算|项目方案)/gi, severity: 'medium' },
            { name: '招投标信息', pattern: /(招标|投标|中标|标书)/gi, severity: 'medium' },
            { name: '手机号', pattern: /1[3-9]\d{9}/g, severity: 'high' },
            { name: '身份证号', pattern: /\d{17}[\dXx]/g, severity: 'high' },
            { name: '银行卡号', pattern: /(62[0-9]{14,17}|4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})/g, severity: 'high' },
            { name: '邮箱地址', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: 'medium' },
            { name: 'IP地址', pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, severity: 'medium' },
            { name: '网址链接', pattern: /https?:\/\/[\w\-._~:/?#@!$&'()*+,;=%\\[\]]+/g, severity: 'low' },
            { name: '密码', pattern: /(password|密码|passwd|pwd)[\s:=]*[a-zA-Z0-9]{6,}/gi, severity: 'high' },
            { name: '账号', pattern: /(账号|用户名|user|username|login)[\s:=]*[a-zA-Z0-9_]{3,}/gi, severity: 'medium' },
            { name: '中文姓名', pattern: /(姓[\u4e00-\u9fa5]{1,3}|名[\u4e00-\u9fa5]{1,3}|姓名[\u4e00-\u9fa5]{1,3})/g, severity: 'low' },
            { name: '详细地址', pattern: /[\u4e00-\u9fa5]+省[\u4e00-\u9fa5]+市[\u4e00-\u9fa5]+区/g, severity: 'medium' },
            { name: '内部标记', pattern: /(仅供内部|内部传阅|请勿外传|保密期限)/gi, severity: 'high' }
        ];
    }

    loadConfig(config) {
        if (!config) return;
        if (config.patterns) {
            Object.keys(config.patterns).forEach(key => {
                const item = config.patterns[key];
                this.patterns.push({
                    name: item.label,
                    pattern: item.regex,
                    severity: item.severity
                });
            });
        }
        if (config.blockedKeywords) {
            config.blockedKeywords.forEach(keyword => {
                this.patterns.push({
                    name: '敏感关键词',
                    pattern: new RegExp(keyword, 'gi'),
                    severity: 'medium'
                });
            });
        }
    }

    setEnabled(enabled) {
        this.enabled = enabled;
    }

    isEnabled() {
        return this.enabled;
    }

    detect(text) {
        if (!this.enabled || !text) {
            return {
                detected: false,
                matches: [],
                riskLevel: 'none',
                highRiskCount: 0,
                mediumRiskCount: 0,
                totalMatches: 0
            };
        }

        const truncatedText = text.length > this.maxDetectionLength
            ? text.substring(0, this.maxDetectionLength)
            : text;

        const detectedSensitiveInfo = [];
        const matchedPatterns = new Set();

        const allPatterns = this.patterns.filter(p => p.pattern instanceof RegExp);
        const highRiskPatterns = allPatterns.filter(p => p.severity === 'high');
        const mediumRiskPatterns = allPatterns.filter(p => p.severity === 'medium');

        let hasHighRisk = false;
        for (const pattern of highRiskPatterns) {
            if (pattern.pattern.test(truncatedText)) {
                hasHighRisk = true;
                break;
            }
        }

        if (hasHighRisk) {
            for (const pattern of highRiskPatterns) {
                const matches = truncatedText.match(pattern.pattern);
                if (matches && matches.length > 0) {
                    const uniqueMatches = [...new Set(matches)].slice(0, 5);
                    detectedSensitiveInfo.push({
                        name: pattern.name,
                        matches: uniqueMatches,
                        count: matches.length,
                        risk: pattern.severity
                    });
                    matchedPatterns.add(pattern.name);
                }
            }
        }

        if (detectedSensitiveInfo.length === 0) {
            for (const pattern of mediumRiskPatterns) {
                const matches = truncatedText.match(pattern.pattern);
                if (matches && matches.length > 0) {
                    const uniqueMatches = [...new Set(matches)].slice(0, 5);
                    detectedSensitiveInfo.push({
                        name: pattern.name,
                        matches: uniqueMatches,
                        count: matches.length,
                        risk: pattern.severity
                    });
                    matchedPatterns.add(pattern.name);
                }
            }
        }

        const highRiskCount = detectedSensitiveInfo.filter(m => m.risk === 'high').reduce((sum, m) => sum + m.count, 0);
        const mediumRiskCount = detectedSensitiveInfo.filter(m => m.risk === 'medium').reduce((sum, m) => sum + m.count, 0);

        let riskLevel = 'none';
        if (highRiskCount > 0) {
            riskLevel = 'high';
        } else if (mediumRiskCount >= 3) {
            riskLevel = 'medium';
        } else if (mediumRiskCount > 0) {
            riskLevel = 'low';
        }

        if (detectedSensitiveInfo.length > 0) {
            this.stats.totalDetections++;
            this.stats.highRiskDetections += highRiskCount;
            this.stats.mediumRiskDetections += mediumRiskCount;
            this.stats.lastDetectionTime = Date.now();
            this.stats.lastDetectedPatterns = detectedSensitiveInfo.slice(0, 5).map(m => m.name);
        }

        return {
            detected: detectedSensitiveInfo.length > 0,
            matches: detectedSensitiveInfo,
            riskLevel: riskLevel,
            highRiskCount: highRiskCount,
            mediumRiskCount: mediumRiskCount,
            totalMatches: detectedSensitiveInfo.length,
            hasHighSeverity: highRiskCount > 0,
            hasSensitiveInfo: detectedSensitiveInfo.length > 0
        };
    }

    getStats() {
        return { ...this.stats };
    }

    resetStats() {
        this.stats = {
            totalDetections: 0,
            highRiskDetections: 0,
            mediumRiskDetections: 0,
            lastDetectionTime: null,
            lastDetectedPatterns: []
        };
    }

    getPatterns() {
        return this.patterns.map(p => ({ name: p.name, risk: p.severity }));
    }

    addPattern(name, pattern, severity = 'medium') {
        this.patterns.push({
            name: name,
            pattern: typeof pattern === 'string' ? new RegExp(pattern, 'gi') : pattern,
            severity: severity
        });
    }

    removePattern(name) {
        this.patterns = this.patterns.filter(p => p.name !== name);
    }

    getDetectionReport() {
        if (this.stats.lastDetectedPatterns.length === 0) {
            return '✅ 未发现敏感信息';
        }
        let report = '❌ 检测到敏感信息：\n\n';
        this.stats.lastDetectedPatterns.forEach(name => {
            const pattern = this.patterns.find(p => p.name === name);
            if (pattern) {
                const severityIcon = pattern.severity === 'high' ? '🔴' : (pattern.severity === 'medium' ? '🟡' : '🟢');
                report += severityIcon + ' ' + name + '\n';
            }
        });
        return report;
    }
}

const privacyDetector = new PrivacyDetector();

if (typeof window !== 'undefined') {
    window.desensitizationProxy = desensitizationProxy;
    window.privacyDetector = privacyDetector;
    window.DesensitizationProxy = DesensitizationProxy;
    window.PrivacyDetector = PrivacyDetector;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DesensitizationProxy, desensitizationProxy, PrivacyDetector, privacyDetector };
}