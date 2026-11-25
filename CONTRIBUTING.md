# 贡献与发布流程 / Contributing and Release Process

## 开发 / Development

```bash
bash build.sh          # 编译 + 全部自测 / compile + all self-tests
bash verify.sh         # 三轮沙盒验收 / three-round sandbox acceptance
```

构建产物为 `wxaudit-burp.jar`，需 JDK 8+；编译用接口桩，打包用 `pack.py` 保证可复现。
Build output is `wxaudit-burp.jar` and requires JDK 8+; compile against stubs and pack with `pack.py` for reproducible output.

## 版本规则 / Versioning

使用语义化版本号。发布时更新版本标记、双语文件索引及必要的安全说明。 / Use semantic versioning. For a release, update the version tag, bilingual file index, and security notes when needed.

## 发布 / Release

```bash
git add .
git commit -m "<中文文件或文件夹说明> / <English file or folder description>"
git tag vX.Y.Z
git push origin main
git push origin vX.Y.Z
```

用 `release.py` 可一键完成推送、建 Release 与上传 jar 附件。/ Use `release.py` to push, create the Release and upload the jar asset in one shot.
PAT 只在命令环境变量中使用，不写入仓库。/ The PAT is used only via environment variable and is never written to the repo.

## 安全 / Security

- 不要提交真实 AppID、令牌、Cookie 或抓包数据。/ Never commit real AppIDs, tokens, cookies or captured traffic.
- 自动化测试使用合成的 wxapkg 与虚构数据。/ Automated tests use synthetic wxapkg files and fictitious data.
- 仅测试自有或已授权目标。/ Only test systems you own or are authorized to test.

<!-- 用途：贡献指南 / Contribution guide | -->
