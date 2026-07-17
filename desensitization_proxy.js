class DesensitizationProxy {
    constructor() {
        this.mapping = {};
        this.counters = {
            phone: 0,
            id: 0,
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
    }

    reset() {
        this.mapping = {};
        this.counters = {
            phone: 0,
            id: 0,
            bank: 0,
            amount: 0,
            company: 0,
            name: 0,
            email: 0,
            wechat: 0,
            custom: 0
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

    simpleEncrypt(text) {
        if (!text) return text;
        let result = '';
        for (let i = 0; i < text.length; i++) {
            result += String.fromCharCode(text.charCodeAt(i) + this.settings.encryptionKey.length);
        }
        return btoa(result);
    }

    simpleDecrypt(text) {
        if (!text) return text;
        try {
            const decoded = atob(text);
            let result = '';
            for (let i = 0; i < decoded.length; i++) {
                result += String.fromCharCode(decoded.charCodeAt(i) - this.settings.encryptionKey.length);
            }
            return result;
        } catch (e) {
            console.error('解密失败:', e);
            return text;
        }
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
        this.settings.customRules.push({
            name: name,
            pattern: new RegExp(pattern, 'g'),
            placeholderPrefix: placeholderPrefix || 'CU'
        });
    }

    removeCustomRule(name) {
        this.settings.customRules = this.settings.customRules.filter(r => r.name !== name);
    }

    desensitize(text) {
        if (!this.settings.enabled) return text;
        
        this.reset();
        const originalLength = text.length;
        
        text = text.replace(/1[3-9]\d{9}/g, (match) => {
            this.counters.phone++;
            const key = '[PH' + this.counters.phone + ']';
            this.mapping[key] = match;
            return key;
        });

        text = text.replace(/\d{17}[\dXx]/g, (match) => {
            this.counters.id++;
            const key = '[ID' + this.counters.id + ']';
            this.mapping[key] = match;
            return key;
        });

        text = text.replace(/\d{16,19}/g, (match) => {
            if (!/^1[3-9]\d{9}$/.test(match)) {
                this.counters.bank++;
                const key = '[BN' + this.counters.bank + ']';
                this.mapping[key] = match;
                return key;
            }
            return match;
        });

        text = text.replace(/(¥|￥)?(\d{1,3}(,\d{3})*(\.\d{2})?)\s*元/g, (match) => {
            this.counters.amount++;
            const key = '[AM' + this.counters.amount + ']';
            this.mapping[key] = match;
            return key;
        });

        text = text.replace(/([\u4e00-\u9fa5]{2,8})(集团|公司|有限公司|股份|控股|有限责任)/g, (match) => {
            this.counters.company++;
            const key = '[CP' + this.counters.company + ']';
            this.mapping[key] = match;
            return key;
        });

        text = text.replace(/\b([\u4e00-\u9fa5]{2,3})(先生|女士|经理|总)\b/g, (match) => {
            if (!match.includes('公司') && !match.includes('集团') && !match.includes('有限')) {
                this.counters.name++;
                const key = '[NM' + this.counters.name + ']';
                this.mapping[key] = match;
                return key;
            }
            return match;
        });

        text = text.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, (match) => {
            this.counters.email++;
            const key = '[EM' + this.counters.email + ']';
            this.mapping[key] = match;
            return key;
        });

        text = text.replace(/(微信号|微信|WeChat|wechat)\s*[:：]?\s*([a-zA-Z0-9_-]{5,})/g, (match) => {
            this.counters.wechat++;
            const key = '[WC' + this.counters.wechat + ']';
            this.mapping[key] = match;
            return key;
        });

        this.settings.customRules.forEach(rule => {
            text = text.replace(rule.pattern, (match) => {
                this.counters.custom++;
                const key = '[' + rule.placeholderPrefix + this.counters.custom + ']';
                this.mapping[key] = match;
                return key;
            });
        });

        const totalReplaced = Object.keys(this.mapping).length;
        this.addLog('desensitize', '数据脱敏完成', {
            originalLength: originalLength,
            replacedCount: totalReplaced,
            categories: this.counters
        });

        return text;
    }

    restore(text) {
        if (!this.settings.enabled) return text;
        
        try {
            Object.keys(this.mapping).forEach((key) => {
                const escapedKey = this.escapeRegExp(key);
                text = text.replace(new RegExp(escapedKey, 'g'), this.mapping[key]);
            });
            
            this.addLog('restore', '数据还原完成', {
                restoredCount: Object.keys(this.mapping).length
            });
        } catch (e) {
            console.error('数据还原失败:', e);
            this.addLog('error', '数据还原失败', { error: e.message });
        }
        return text;
    }

    getMapping() {
        return JSON.parse(JSON.stringify(this.mapping));
    }

    setMapping(mapping) {
        this.mapping = JSON.parse(JSON.stringify(mapping));
    }

    encryptMapping() {
        const jsonStr = JSON.stringify(this.mapping);
        return this.simpleEncrypt(jsonStr);
    }

    decryptMapping(encrypted) {
        try {
            const jsonStr = this.simpleDecrypt(encrypted);
            this.mapping = JSON.parse(jsonStr);
            return true;
        } catch (e) {
            console.error('映射表解密失败:', e);
            return false;
        }
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

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DesensitizationProxy, desensitizationProxy };
}