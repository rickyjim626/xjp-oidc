#!/bin/bash

# SBOM 生成脚本
# 生成多种格式的软件物料清单

set -e

echo "🔍 开始生成 SBOM..."

# 检查必要的工具
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ 缺少工具: $1"
        echo "   请安装: $2"
        exit 1
    fi
}

# 创建输出目录
OUTPUT_DIR="sbom-output"
mkdir -p "$OUTPUT_DIR"

# 生成时间戳
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# 1. 使用 cargo-sbom 生成基础 SBOM
if command -v cargo-sbom &> /dev/null; then
    echo "📦 使用 cargo-sbom 生成..."
    
    # CycloneDX 格式
    cargo sbom --format cyclonedx-json > "$OUTPUT_DIR/sbom-cargo-cyclonedx-$TIMESTAMP.json"
    cargo sbom --format cyclonedx-xml > "$OUTPUT_DIR/sbom-cargo-cyclonedx-$TIMESTAMP.xml"
    
    # SPDX 格式
    cargo sbom --format spdx-json > "$OUTPUT_DIR/sbom-cargo-spdx-$TIMESTAMP.json"
else
    echo "⚠️  cargo-sbom 未安装，跳过"
    echo "   安装: cargo install cargo-sbom"
fi

# 2. 使用 syft 生成详细 SBOM
if command -v syft &> /dev/null; then
    echo "📦 使用 syft 生成..."
    
    syft . -o cyclonedx-json > "$OUTPUT_DIR/sbom-syft-cyclonedx-$TIMESTAMP.json"
    syft . -o spdx-json > "$OUTPUT_DIR/sbom-syft-spdx-$TIMESTAMP.json"
    syft . -o github > "$OUTPUT_DIR/sbom-syft-github-$TIMESTAMP.json"
    
    # 生成可读的表格格式
    syft . -o table > "$OUTPUT_DIR/sbom-syft-table-$TIMESTAMP.txt"
else
    echo "⚠️  syft 未安装，跳过"
    echo "   安装: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
fi

# 3. 使用 cargo tree 生成依赖树
echo "🌳 生成依赖树..."
cargo tree > "$OUTPUT_DIR/dependency-tree-$TIMESTAMP.txt"
cargo tree --duplicates > "$OUTPUT_DIR/dependency-duplicates-$TIMESTAMP.txt"

# 4. 生成许可证报告
echo "📄 生成许可证报告..."
if command -v cargo-license &> /dev/null; then
    cargo license --json > "$OUTPUT_DIR/licenses-$TIMESTAMP.json"
    cargo license > "$OUTPUT_DIR/licenses-$TIMESTAMP.txt"
else
    echo "⚠️  cargo-license 未安装"
    echo "   安装: cargo install cargo-license"
fi

# 5. 生成汇总报告
echo "📊 生成汇总报告..."
cat > "$OUTPUT_DIR/sbom-summary-$TIMESTAMP.md" << EOF
# SBOM 生成报告

生成时间: $(date)
项目: xjp-oidc
版本: $(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)

## 生成的文件

$(ls -la "$OUTPUT_DIR" | grep "$TIMESTAMP")

## 依赖统计

- 直接依赖数量: $(cargo tree --depth 1 | grep -c "├──\|└──" || echo "0")
- 总依赖数量: $(cargo tree | grep -c "├──\|└──" || echo "0")

## 许可证统计

$(if [ -f "$OUTPUT_DIR/licenses-$TIMESTAMP.txt" ]; then
    echo "最常见的许可证:"
    grep -E "MIT|Apache-2.0|BSD" "$OUTPUT_DIR/licenses-$TIMESTAMP.txt" | sort | uniq -c | sort -nr | head -10
else
    echo "许可证信息不可用"
fi)

## 安全建议

1. 定期更新此 SBOM
2. 使用 grype 或 trivy 扫描漏洞
3. 检查许可证合规性
4. 监控依赖更新

EOF

# 6. 创建最新版本的符号链接
echo "🔗 创建符号链接..."
cd "$OUTPUT_DIR"
for file in *-$TIMESTAMP.*; do
    base=$(echo "$file" | sed "s/-$TIMESTAMP//")
    ln -sf "$file" "$base"
done
cd ..

echo "✅ SBOM 生成完成！"
echo "📁 输出目录: $OUTPUT_DIR"
echo ""
echo "下一步:"
echo "1. 扫描漏洞: grype sbom:$OUTPUT_DIR/sbom-syft-cyclonedx.json"
echo "2. 签名 SBOM: cosign sign-blob $OUTPUT_DIR/sbom-syft-cyclonedx.json"
echo "3. 上传到 GitHub Release 或制品库"