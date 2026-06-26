# Google 账号邮箱前缀可用性批量检测

批量检测你想改用的 Gmail 前缀(如 `xxx@gmail.com` 的 `xxx`)是否已被占用。
原理:复用 `myaccount.google.com` "修改邮箱地址"页面里 `rpcids=chspYe` 的实时检查接口,
把单个请求变成按列表批量探测。

> ⚠️ 仅用于检测**你自己账号**想用的前缀。Google 风控严格,请保持默认延迟,不要并发、不要批量探测他人地址。

## 文件说明

| 文件 | 作用 |
|------|------|
| `check_gmail_alias.py` | 主脚本 |
| `.env` | 你的账号凭据(从 `.env.example` 复制后填,**不入库**) |
| `.env.example` | 凭据格式样例(占位假数据,可入库参考) |
| `probe.txt` | 抓包来的 cURL,导入凭据用(从 `probe.example.txt` 复制后填,**不入库**) |
| `probe.example.txt` | cURL 格式样例 + 抓包说明(可入库参考) |
| `names.txt` | 候选前缀列表(从 `names.example.txt` 复制后改成你的) |
| `names.example.txt` | 候选名单样例 + 规则说明(可入库参考) |
| `results.csv` | 运行后生成,保存每个前缀的判定结果(不入库) |

> 首次使用:复制三份样例为实际文件
> ```bash
> copy .env.example .env        # 填凭据
> copy probe.example.txt probe.txt   # 填 cURL
> copy names.example.txt names.txt   # 填候选前缀
> ```

---

## 使用步骤(推荐:.env 多账号切换)

凭据(cookie / at / rapt / f.sid / PSIDTS)有时效且每个账号不同。把凭据放 `.env`,
切换账号只改 `--account` 一个参数,不用每次重抓整条 curl。

依赖:`pip install requests python-dotenv`(后者可选,没装会降级用系统环境变量)。

### 1. 抓一条 curl 并导出成 .env 片段

浏览器登录账号 → myaccount「修改邮箱」页 → 浏览器 DevTools 抓到 `chspYe` 那条请求 →
**Copy as cURL (bash)** 粘进 `template.txt`,然后:
<img width="1920" height="869" alt="d78d3b6e0867f214" src="https://github.com/user-attachments/assets/61c59c98-d734-4a7e-a5cd-e9be35b14275" />

```bash
python check_gmail_alias.py --import-curl main -f template.txt
```

会打印一段 `# ── 账号 MAIN ──` 开头的文本,把它**整段粘进 `.env`**(覆盖同名账号即可)。
`.env` 长这样,可放多个账号:

```dotenv
# ── 账号 MAIN ──
MAIN_U=0
MAIN_FSID=你的f.sid
MAIN_BL=boq_identityaccountsettingsuiserver_20260622.07_p0
MAIN_RAPT=你的rapt
MAIN_AT=你的at:时间戳
MAIN_COOKIE=SID=你的; __Secure-1PSID=你的; __Secure-1PSIDTS=sidts-你的; ...

# ── 账号 WORK ──
WORK_U=0
WORK_FSID=...
WORK_COOKIE=...
WORK_AT=...
```

> 切换账号 = 改 `--account` 那个名字(对应 `.env` 里前缀),如 `--account work`。
> ⚠️ `.env` 含登录凭据,已在 `.gitignore`,**切勿提交/外传**。

### 2. 填候选前缀

编辑 `names.txt`,每行一个(`#` 开头注释)。

### 3. 跑(用 .env 账号)

```bash
python check_gmail_alias.py --account main --names-file names.txt
```

常用参数:

```
--account main             用 .env 里哪个账号(推荐)
--import-curl <名> -f curl文件   抓包后导出 .env 片段
--names a,b,c               不用文件,直接传逗号分隔前缀
--delay 2 --jitter 1        间隔 2 秒 + 抖动(默认,实测连发数百次零风控)
--proxy http://127.0.0.1:8080   走抓包代理实时观察
--dry-run                   只构造不发送,自检
--skip-validate             跳过本地前缀合法性预校验
```

### 旧方式(仍然支持)

不想用 `.env` 时,可直接喂整条 curl:

```bash
python check_gmail_alias.py --curl-file template.txt --names-file names.txt
```

### 看结果

控制台实时打印,同时写 `results.csv`:`verdict` = `AVAILABLE`/`TAKEN`/`UNAVAILABLE`/`UNKNOWN`/`ERROR`。

## 判定规则

接口返回 `[status, [替代建议...], "前缀@gmail.com"]`。**唯一正确的判定依据是 payload 第一位 `status`**(经真实抓包实证):

- `status == 1` → **AVAILABLE 可用**(可注册)
- `status == 2` → **TAKEN 已被占用**,同时返回 3 个替代建议
- `status == 0` → **UNAVAILABLE 系统不允许**(被保留/受限/属被冻结账号,**既不是占用也不是可用**)
- 解析不到响应 → **UNKNOWN**(风控或登录态失效)

> ⚠️ **易错点**:不要用"有没有替代建议"判可用!`status=0` 时替代建议也是空的,会被误判成可用
> (常见英文词/人名如 `valeria`/`aurelia` 都是 status=0,系统会拒绝)。**只认 status==1。**
>
> 实测样本:`nhcfnghcmgc`=status1(可用)、`valeria`=status0(不允许)、`8888888`=status2(占用)。
>
> 另一个坑:请求头必须带 `x-goog-ext-525002608-jspb: [507]`,否则服务器返回 gRPC 错误码
> `[16]`(UNAUTHENTICATED),所有名字都一样、无 alternatives,会被误判。凭证过期时同样如此 ——
> 跑之前务必重新抓一条新鲜 curl。

## 友情链接

- [linux.do](https://linux.do/)
