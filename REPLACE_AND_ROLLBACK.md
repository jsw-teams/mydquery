# 覆盖替换 / 清理旧版本 / 回滚

## 一、覆盖前清理旧版本

```bash
systemctl stop dqueryd 2>/dev/null || true
rm -f /etc/systemd/system/dqueryd.service
rm -f /opt/dqueryd/bin/dqueryd
rm -f /opt/dqueryd/bin/chinamax-build
rm -rf /opt/dqueryd-src/*
systemctl daemon-reload
```

## 二、备份当前版本

```bash
mkdir -p /root/dqueryd-backup
[ -d /opt/dqueryd-src ] && tar -C /opt -czf /root/dqueryd-backup/dqueryd-src-$(date +%F-%H%M%S).tar.gz dqueryd-src || true
[ -d /etc/dqueryd ] && tar -C /etc -czf /root/dqueryd-backup/etc-dqueryd-$(date +%F-%H%M%S).tar.gz dqueryd || true
[ -d /var/lib/dqueryd ] && tar -C /var/lib -czf /root/dqueryd-backup/var-lib-dqueryd-$(date +%F-%H%M%S).tar.gz dqueryd || true
```

## 三、覆盖新版本

```bash
mkdir -p /opt/dqueryd-src
unzip -oq /root/gateway-dquery-go-refactored.zip -d /opt/dqueryd-src
cd /opt/dqueryd-src

go mod tidy
go build -trimpath -ldflags="-s -w" -o /opt/dqueryd/bin/dqueryd ./cmd/dqueryd
go build -trimpath -ldflags="-s -w" -o /opt/dqueryd/bin/chinamax-build ./cmd/chinamax-build

cp -f /opt/dqueryd-src/deploy/systemd/dqueryd.service /etc/systemd/system/dqueryd.service
systemctl daemon-reload
systemctl enable --now dqueryd
systemctl status dqueryd --no-pager -l
```

## 四、快速回滚

把你备份的 tar.gz 解回去即可，例如：

```bash
systemctl stop dqueryd
rm -rf /opt/dqueryd-src /etc/dqueryd /var/lib/dqueryd
mkdir -p /opt /etc /var/lib

tar -C /opt -xzf /root/dqueryd-backup/dqueryd-src-YYYY-MM-DD-HHMMSS.tar.gz
tar -C /etc -xzf /root/dqueryd-backup/etc-dqueryd-YYYY-MM-DD-HHMMSS.tar.gz
tar -C /var/lib -xzf /root/dqueryd-backup/var-lib-dqueryd-YYYY-MM-DD-HHMMSS.tar.gz

systemctl daemon-reload
systemctl enable --now dqueryd
systemctl status dqueryd --no-pager -l
```
