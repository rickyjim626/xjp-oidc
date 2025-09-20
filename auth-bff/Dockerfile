# 构建阶段
FROM rust:1.82-slim AS builder

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /usr/src/app

# 复制整个工作区
COPY . .

# 构建 auth-bff
RUN cargo build --release -p auth-bff

# 运行阶段
FROM debian:bookworm-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# 创建非 root 用户
RUN useradd -m -u 1001 app

# 复制二进制文件
COPY --from=builder /usr/src/app/target/release/auth-bff /usr/local/bin/auth-bff

# 设置权限
RUN chmod +x /usr/local/bin/auth-bff

# 切换到非 root 用户
USER app

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# 启动应用
CMD ["auth-bff"]