#!/bin/bash

# 安全扫描脚本
# 执行多种安全检查

set -e

echo "🔒 开始安全扫描..."
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 结果统计
TOTAL_ISSUES=0
CRITICAL_ISSUES=0

# 创建报告目录
REPORT_DIR="security-reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# 1. Rust 安全审计
echo "1️⃣ 运行 cargo audit..."
if command -v cargo-audit &> /dev/null; then
    if cargo audit 2>&1 | tee "$REPORT_DIR/cargo-audit-$TIMESTAMP.txt"; then
        echo -e "${GREEN}✅ 未发现已知漏洞${NC}"
    else
        echo -e "${RED}❌ 发现安全漏洞${NC}"
        ((TOTAL_ISSUES++))
        ((CRITICAL_ISSUES++))
    fi
else
    echo -e "${YELLOW}⚠️  cargo-audit 未安装${NC}"
    echo "   安装: cargo install cargo-audit"
fi
echo ""

# 2. 依赖更新检查
echo "2️⃣ 检查过期的依赖..."
if command -v cargo-outdated &> /dev/null; then
    cargo outdated --exit-code 1 > "$REPORT_DIR/outdated-$TIMESTAMP.txt" 2>&1 || {
        echo -e "${YELLOW}⚠️  发现过期的依赖${NC}"
        cat "$REPORT_DIR/outdated-$TIMESTAMP.txt"
        ((TOTAL_ISSUES++))
    }
else
    echo -e "${YELLOW}⚠️  cargo-outdated 未安装${NC}"
    echo "   安装: cargo install cargo-outdated"
fi
echo ""

# 3. 许可证检查
echo "3️⃣ 检查许可证合规性..."
if command -v cargo-deny &> /dev/null; then
    cargo deny check licenses 2>&1 | tee "$REPORT_DIR/licenses-$TIMESTAMP.txt" || {
        echo -e "${YELLOW}⚠️  发现许可证问题${NC}"
        ((TOTAL_ISSUES++))
    }
else
    echo -e "${YELLOW}⚠️  cargo-deny 未安装${NC}"
    echo "   安装: cargo install cargo-deny"
fi
echo ""

# 4. 代码安全检查
echo "4️⃣ 运行 clippy 安全检查..."
cargo clippy --all-targets --all-features -- \
    -W clippy::unwrap_used \
    -W clippy::expect_used \
    -W clippy::panic \
    -W clippy::unimplemented \
    -W clippy::todo \
    2>&1 | tee "$REPORT_DIR/clippy-security-$TIMESTAMP.txt" || {
    echo -e "${YELLOW}⚠️  发现潜在的代码问题${NC}"
    ((TOTAL_ISSUES++))
}
echo ""

# 5. 敏感信息扫描
echo "5️⃣ 扫描敏感信息..."
SECRETS_FOUND=0

# 检查常见的敏感模式
patterns=(
    "password.*=.*['\"].*['\"]"
    "api[_-]?key.*=.*['\"].*['\"]"
    "secret.*=.*['\"].*['\"]"
    "token.*=.*['\"].*['\"]"
    "private[_-]?key"
    "BEGIN.*PRIVATE KEY"
)

for pattern in "${patterns[@]}"; do
    if grep -r -i -E "$pattern" --include="*.rs" --include="*.toml" --exclude-dir=target . > /dev/null 2>&1; then
        echo -e "${RED}❌ 发现可能的敏感信息: $pattern${NC}"
        ((SECRETS_FOUND++))
        ((TOTAL_ISSUES++))
        ((CRITICAL_ISSUES++))
    fi
done

if [ $SECRETS_FOUND -eq 0 ]; then
    echo -e "${GREEN}✅ 未发现明显的敏感信息${NC}"
fi
echo ""

# 6. SBOM 漏洞扫描
echo "6️⃣ 扫描 SBOM 漏洞..."
if [ -f "sbom-output/sbom-syft-cyclonedx.json" ]; then
    if command -v grype &> /dev/null; then
        grype sbom:sbom-output/sbom-syft-cyclonedx.json -o table > "$REPORT_DIR/grype-$TIMESTAMP.txt" 2>&1 || {
            echo -e "${RED}❌ 发现漏洞${NC}"
            cat "$REPORT_DIR/grype-$TIMESTAMP.txt" | grep -E "Critical|High" || true
            ((TOTAL_ISSUES++))
        }
    else
        echo -e "${YELLOW}⚠️  grype 未安装${NC}"
        echo "   安装: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
    fi
else
    echo -e "${YELLOW}⚠️  未找到 SBOM 文件，请先运行 ./scripts/generate-sbom.sh${NC}"
fi
echo ""

# 7. 生成综合报告
echo "7️⃣ 生成安全报告..."
cat > "$REPORT_DIR/security-summary-$TIMESTAMP.md" << EOF
# 安全扫描报告

扫描时间: $(date)
项目: xjp-oidc

## 扫描结果摘要

- 总问题数: $TOTAL_ISSUES
- 严重问题: $CRITICAL_ISSUES
- 扫描项目:
  - [x] Cargo audit
  - [x] 依赖更新检查
  - [x] 许可证合规
  - [x] Clippy 安全检查
  - [x] 敏感信息扫描
  - [x] SBOM 漏洞扫描

## 详细报告

详细报告保存在 \`$REPORT_DIR\` 目录中：

$(ls -la "$REPORT_DIR" | grep "$TIMESTAMP" | awk '{print "- " $9}')

## 建议

1. 修复所有严重漏洞
2. 更新过期的依赖
3. 检查并移除任何敏感信息
4. 定期运行此扫描

EOF

# 显示总结
echo "📊 扫描完成！"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "总问题数: ${YELLOW}$TOTAL_ISSUES${NC}"
echo -e "严重问题: ${RED}$CRITICAL_ISSUES${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📁 详细报告: $REPORT_DIR/security-summary-$TIMESTAMP.md"

# 根据结果返回退出码
if [ $CRITICAL_ISSUES -gt 0 ]; then
    exit 1
else
    exit 0
fi