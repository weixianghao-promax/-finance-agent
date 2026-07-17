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
            wechat: 0
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
            wechat: 0
        };
    }

    escapeRegExp(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    desensitize(text) {
        this.reset();
        
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

        return text;
    }

    restore(text) {
        try {
            Object.keys(this.mapping).forEach((key) => {
                const escapedKey = this.escapeRegExp(key);
                text = text.replace(new RegExp(escapedKey, 'g'), this.mapping[key]);
            });
        } catch (e) {
            console.error('数据还原失败:', e);
        }
        return text;
    }

    getMapping() {
        return JSON.parse(JSON.stringify(this.mapping));
    }

    setMapping(mapping) {
        this.mapping = JSON.parse(JSON.stringify(mapping));
    }
}

const desensitizationProxy = new DesensitizationProxy();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DesensitizationProxy, desensitizationProxy };
}