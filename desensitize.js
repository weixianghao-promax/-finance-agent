function desensitizeFileData(rawContent, options) {
    if (!rawContent || typeof rawContent !== 'string') {
        return rawContent || '';
    }

    const config = {
        maskPhone: true,
        maskIdCard: true,
        maskCompanyName: true,
        maskContractNo: true,
        maskFinanceAmount: false,
        maskBankCard: true,
        maskEmail: true,
        maskName: true,
        maskWechat: true,
        maskPassword: true,
        maskAccount: true,
        ...options
    };

    let result = rawContent;

    if (config.maskPhone) {
        result = result.replace(/1[3-9]\d{9}/g, function(match) {
            return match.substring(0, 3) + '****' + match.substring(7);
        });
    }

    if (config.maskIdCard) {
        result = result.replace(/\d{17}[\dXx]/g, function(match) {
            return match.substring(0, 6) + '***********' + match.substring(17);
        });
    }

    if (config.maskBankCard) {
        result = result.replace(/(62[0-9]{14,17}|4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})/g, function(match) {
            if (match.length >= 16) {
                return match.substring(0, 4) + '********' + match.substring(12);
            }
            return match.substring(0, 4) + '****' + match.substring(8);
        });
    }

    if (config.maskEmail) {
        result = result.replace(/([a-zA-Z0-9._%+-]{1,3})[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g, '$1****@$2');
    }

    if (config.maskCompanyName) {
        result = result.replace(/([\u4e00-\u9fa5]{2,8})(集团|公司|有限公司|股份|控股|有限责任)/g, function(match, name, suffix) {
            if (name.length <= 2) {
                return name.charAt(0) + '*' + suffix;
            }
            return name.charAt(0) + '**' + suffix;
        });
    }

    if (config.maskContractNo) {
        result = result.replace(/(合同编号|合同号|协议编号|协议号)\s*[:：]?\s*([A-Za-z0-9\-]{8,})/g, '$1：****');
        result = result.replace(/([A-Za-z]{2,4}[\-]?\d{8,20})/g, function(match) {
            return match.substring(0, 4) + '********';
        });
    }

    if (config.maskFinanceAmount) {
        result = result.replace(/(¥|￥)?(\d{1,3}(,\d{3})*(\.\d{2})?)\s*元/g, '****元');
        result = result.replace(/(\d{1,3}(,\d{3})*(\.\d{2})?)\s*(万元|亿元)/g, '****$2');
    }

    if (config.maskName) {
        result = result.replace(/\b([\u4e00-\u9fa5]{2,3})(先生|女士|经理|总|主任)\b/g, function(match, name, title) {
            if (name.length === 2) {
                return name.charAt(0) + '*' + title;
            }
            return name.charAt(0) + '*' + name.charAt(name.length - 1) + title;
        });
    }

    if (config.maskWechat) {
        result = result.replace(/(微信号|微信|WeChat|wechat)\s*[:：]?\s*([a-zA-Z0-9_-]{5,})/g, '$1：****');
    }

    if (config.maskPassword) {
        result = result.replace(/(password|密码|passwd|pwd)[\s:=]*[a-zA-Z0-9]{6,}/gi, '$1：****');
    }

    if (config.maskAccount) {
        result = result.replace(/(账号|用户名|user|username|login)[\s:=]*[a-zA-Z0-9_]{3,}/gi, '$1：****');
    }

    return result;
}

function detectSensitiveInfo(content) {
    if (!content || typeof content !== 'string') {
        return { detected: false, matches: [], riskLevel: 'none' };
    }

    const patterns = [
        { name: '手机号', pattern: /1[3-9]\d{9}/g, severity: 'high' },
        { name: '身份证号', pattern: /\d{17}[\dXx]/g, severity: 'high' },
        { name: '银行卡号', pattern: /(62[0-9]{14,17}|4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})/g, severity: 'high' },
        { name: '邮箱地址', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: 'medium' },
        { name: '公司名称', pattern: /([\u4e00-\u9fa5]{2,8})(集团|公司|有限公司|股份|控股|有限责任)/g, severity: 'medium' },
        { name: '合同编号', pattern: /(合同编号|合同号|协议编号|协议号)\s*[:：]?\s*([A-Za-z0-9\-]{8,})/g, severity: 'high' },
        { name: '密码', pattern: /(password|密码|passwd|pwd)[\s:=]*[a-zA-Z0-9]{6,}/gi, severity: 'high' },
        { name: '账号', pattern: /(账号|用户名|user|username|login)[\s:=]*[a-zA-Z0-9_]{3,}/gi, severity: 'medium' },
        { name: '微信号', pattern: /(微信号|微信|WeChat|wechat)\s*[:：]?\s*([a-zA-Z0-9_-]{5,})/g, severity: 'medium' },
        { name: '机密标记', pattern: /(机密|绝密|保密|内部资料|内部文件|内部信息)/gi, severity: 'high' },
        { name: '商业秘密', pattern: /(商业秘密|商业机密|知识产权|专利|技术秘密)/gi, severity: 'high' },
        { name: '财务数据', pattern: /(财务报表|财务数据|审计报告|纳税申报|发票号码|银行账户)/gi, severity: 'high' },
        { name: '客户信息', pattern: /(客户名单|客户资料|客户信息|客户联系方式)/gi, severity: 'high' },
        { name: '员工信息', pattern: /(员工名单|薪资|工资|薪酬|年终奖)/gi, severity: 'medium' },
        { name: '项目机密', pattern: /(项目计划|项目进度|项目预算|项目方案)/gi, severity: 'medium' },
        { name: '招投标信息', pattern: /(招标|投标|中标|标书|报价单)/gi, severity: 'medium' },
        { name: 'IP地址', pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, severity: 'medium' },
        { name: '网址链接', pattern: /https?:\/\/[\w\-._~:/?#@!$&'()*+,;=%\\[\]]+/g, severity: 'low' },
        { name: '详细地址', pattern: /[\u4e00-\u9fa5]+省[\u4e00-\u9fa5]+市[\u4e00-\u9fa5]+区/g, severity: 'medium' },
        { name: '中文姓名', pattern: /(姓[\u4e00-\u9fa5]{1,3}|名[\u4e00-\u9fa5]{1,3}|姓名[\u4e00-\u9fa5]{1,3})/g, severity: 'low' }
    ];

    const detected = [];
    let highRiskCount = 0;
    let mediumRiskCount = 0;

    patterns.forEach(pattern => {
        const matches = content.match(pattern.pattern);
        if (matches && matches.length > 0) {
            const uniqueMatches = [...new Set(matches)].slice(0, 5);
            detected.push({
                name: pattern.name,
                matches: uniqueMatches,
                count: matches.length,
                severity: pattern.severity
            });
            if (pattern.severity === 'high') {
                highRiskCount += matches.length;
            } else if (pattern.severity === 'medium') {
                mediumRiskCount += matches.length;
            }
        }
    });

    let riskLevel = 'none';
    if (highRiskCount > 0) {
        riskLevel = 'high';
    } else if (mediumRiskCount >= 3) {
        riskLevel = 'medium';
    } else if (mediumRiskCount > 0) {
        riskLevel = 'low';
    }

    return {
        detected: detected.length > 0,
        matches: detected,
        riskLevel: riskLevel,
        highRiskCount: highRiskCount,
        mediumRiskCount: mediumRiskCount,
        totalMatches: detected.length,
        hasHighSeverity: highRiskCount > 0
    };
}

if (typeof window !== 'undefined') {
    window.desensitizeFileData = desensitizeFileData;
    window.detectSensitiveInfo = detectSensitiveInfo;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        desensitizeFileData,
        detectSensitiveInfo
    };
}