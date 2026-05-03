# VPS 部署说明（Debian 12 / root）

## 1. 目录规划

```bash
mkdir -p /opt/dqueryd-src /opt/dqueryd/bin /opt/dqueryd/vendor /etc/dqueryd /var/lib/dqueryd /var/log/dqueryd
```

## 2. 上传源码包并解压

把本项目 ZIP 上传到 VPS，例如 `/root/gateway-dquery-go-refactored.zip`：

```bash
rm -rf /opt/dqueryd-src/*
unzip -oq /root/gateway-dquery-go-refactored.zip -d /opt/dqueryd-src
cd /opt/dqueryd-src
```

## 3. 编译

```bash
go mod tidy
go build -trimpath -ldflags="-s -w" -o /opt/dqueryd/bin/dqueryd ./cmd/dqueryd
go build -trimpath -ldflags="-s -w" -o /opt/dqueryd/bin/chinamax-build ./cmd/chinamax-build
```

## 4. 下载 ChinaMax 规则文件

```bash
curl -L 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Classical.yaml'   -o /opt/dqueryd/vendor/ChinaMax_Classical.yaml
```

## 5. 生成运行时规则

```bash
/opt/dqueryd/bin/chinamax-build   -src /opt/dqueryd/vendor/ChinaMax_Classical.yaml   -include /opt/dqueryd-src/data/local-include.txt   -exclude /opt/dqueryd-src/data/local-exclude.txt   -out /var/lib/dqueryd/chinamax_classical.compact.json
```

## 6. 写入配置文件

```bash
cp -f /opt/dqueryd-src/configs/config.example.yaml /etc/dqueryd/config.yaml
```

需要按你的环境改的通常是：

- `upstreams.selfhosted_cn_1.url`
- `upstreams.selfhosted_cn_1.headers.X-Upstream-Key`
- `upstreams.cloudflare_gateway_global.url`
- 监听地址与缓存参数

## 7. 创建服务用户

```bash
id dqueryd >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin dqueryd
chown -R dqueryd:dqueryd /var/lib/dqueryd /var/log/dqueryd
chown -R root:root /opt/dqueryd /opt/dqueryd-src /etc/dqueryd
chmod 755 /opt/dqueryd /opt/dqueryd/bin /opt/dqueryd-src /etc/dqueryd
chmod 644 /etc/dqueryd/config.yaml
chmod 755 /opt/dqueryd/bin/dqueryd /opt/dqueryd/bin/chinamax-build
```

## 8. 安装 systemd 服务

```bash
cp -f /opt/dqueryd-src/deploy/systemd/dqueryd.service /etc/systemd/system/dqueryd.service
systemctl daemon-reload
systemctl enable --now dqueryd
systemctl status dqueryd --no-pager -l
```

## 9. 健康检查

```bash
curl -sS http://127.0.0.1:18053/api/v1/dquery/healthz
curl -sS http://127.0.0.1:18053/api/v1/dquery/readyz
journalctl -u dqueryd -n 100 --no-pager
```

## 10. 接入 OpenResty

### http {} 级别

```bash
cp -f /opt/dqueryd-src/deploy/openresty/zz_dqueryd_support.conf /usr/local/openresty/nginx/conf/conf.d/zz_dqueryd_support.conf
```

### gateway.js.gripe 的 server {} 内

把下面这行加入现有站点配置：

```nginx
include /usr/local/openresty/nginx/conf/conf.d/gateway.js.gripe.dquery.locations.conf;
```

再复制 location 片段：

```bash
cp -f /opt/dqueryd-src/deploy/openresty/gateway.js.gripe.dquery.locations.conf /usr/local/openresty/nginx/conf/conf.d/gateway.js.gripe.dquery.locations.conf
/usr/local/openresty/nginx/sbin/nginx -t && /usr/local/openresty/nginx/sbin/nginx -s reload
```
