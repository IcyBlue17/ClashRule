function main(config) {
    if (!config || typeof config !== "object") return config;
    if (!config["proxy-providers"]) config["proxy-providers"] = {};
    //请自行替换两个方向的订阅链接
    const SHENGANG_PROVIDER = "shengang";
    const HURI_PROVIDER = "huri";
    if (!config["proxy-providers"][SHENGANG_PROVIDER]) {
        config["proxy-providers"][SHENGANG_PROVIDER] = {
            type: "http",
            url: "https://ys.mihoyo.com",//替换为深港方向订阅链接
            interval: 3600,
            path: "./providers/shengang.yaml",
            "health-check": {
                enable: true,
                interval: 600,
                url: "https://ping.11451919.xyz"
            },
            //覆写自行修改
            override: {
                udp: true,
                "skip-cert-verify": true
            }
        };
    }
    if (!config["proxy-providers"][HURI_PROVIDER]) {
        config["proxy-providers"][HURI_PROVIDER] = {
            type: "http",
            url: "https://df.qq.com", //替换为沪日方向订阅链接
            interval: 3600,
            path: "./providers/huri.yaml",
            "health-check": {
                enable: true,
                interval: 600,
                url: "https://ping.11451919.xyz/"
            },
            //自行编辑覆写
            override: {
                udp: true,
                "skip-cert-verify": true
            }
        };
    }
    if (!Array.isArray(config["proxy-groups"])) config["proxy-groups"] = [];
    const GROUP_SHENGANG = "深港方向";
    const GROUP_HURI = "沪日方向";
    function ensureSelectGroup(name, providerKey) {
        let g = config["proxy-groups"].find(x => x && x.name === name);
        if (!g) {
            g = { name, type: "select", use: [providerKey] };
            config["proxy-groups"].unshift(g);
        } else {
            g.type = "select";
            if (!Array.isArray(g.use)) g.use = [];
            if (!g.use.includes(providerKey)) g.use.push(providerKey);
        }
    }

    ensureSelectGroup(GROUP_SHENGANG, SHENGANG_PROVIDER);
    ensureSelectGroup(GROUP_HURI, HURI_PROVIDER);
    //根据节点名称分配代理
    const REG_SG_HK_TW = /(SG|新加坡|狮城|🇸🇬|HK|香港|🇭🇰|TW|台湾|台灣|🇹🇼)/i;
    const REG_JP_US_KR = /(JP|US|美国|United States|America|🇺🇸|KR|韩国|韓國|🇰🇷)/i;

    if (Array.isArray(config.proxies)) {
        config.proxies.forEach(p => {
            if (!p || typeof p.name !== "string") return;
            const name = p.name;
            if (REG_SG_HK_TW.test(name)) {
                p["dialer-proxy"] = GROUP_SHENGANG;
            } else if (REG_JP_US_KR.test(name)) {
                p["dialer-proxy"] = GROUP_HURI;
            }
        });
    }

    return config;
}
if (typeof module !== "undefined" && module.exports) {
    module.exports = { main };
} else if (typeof exports !== "undefined") {
    exports.main = main;
}