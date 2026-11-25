# 贡献与发布流程 / Contributing and Release Process

## 开发 / Development

```bash
bash build.sh          # 编译 + 全部自测 / compile + all self-tests
bash verify.sh         # 三轮沙盒验收 / three-round sandbox acceptance
```

构建产物为 `wxaudit-burp.jar`，需 JDK 8+；编译用接口桩，打包用 `pack.py` 保证可复现。
Build output is `wxaudit-burp.jar` and requires JDK 8+; compile against stubs and pack with `pack.py` for reproducible output.

## 版本规则 / Versioning

- `1.0.x`: 首个稳定版 / first stable release
- 后续采用语义化版本 / semantic versioning thereafter

一起更新下列文件：/ Update all of these together:

- `CHANGELOG.md`
- `README.md` / `README.en.md` 的版本号 / version headers
- `RELEASE_NOTES.md`

## 发布 / Release

```bash
git add .
git commit -m "release: v1.0.0"
git tag v1.0.0
git push origin main
git push origin v1.0.0
```

用 `release.py` 可一键完成推送、建 Release 与上传 jar 附件。/ Use `release.py` to push, create the Release and upload the jar asset in one shot.
PAT 只在命令环境变量中使用，不写入仓库。/ The PAT is used only via environment variable and is never written to the repo.

## 安全 / Security

- 不要提交真实 AppID、令牌、Cookie 或抓包数据。/ Never commit real AppIDs, tokens, cookies or captured traffic.
- 自动化测试使用合成的 wxapkg 与虚构数据。/ Automated tests use synthetic wxapkg files and fictitious data.
- 仅测试自有或已授权目标。/ Only test systems you own or are authorized to test.

<!-- 用途：贡献指南 / Contribution guide | -->
