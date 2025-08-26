# Dockerfile (Optimized Version)
FROM node:18-slim
WORKDIR /app

# 1. [保持不变] 安装系统依赖。这是最稳定的部分，放在最前面。
RUN apt-get update && apt-get install -y \
    curl \
    libasound2 libatk-bridge2.0-0 libatk1.0-0 libatspi2.0-0 libcups2 \
    libdbus-1-3 libdrm2 libgbm1 libgtk-3-0 libnspr4 libnss3 libx11-6 \
    libx11-xcb1 libxcb1 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
    libxrandr2 libxss1 libxtst6 xvfb \
    && rm -rf /var/lib/apt/lists/*

# 2. [保持不变] 拷贝 package.json 并安装依赖。
# 这是第二稳定的部分，只要依赖不变，这一层就会被缓存。
COPY package*.json ./
RUN npm install --production

# 3. [优化] 将 Camoufox 的下载移动到 npm install 之后。
# 这样，即使 CAMOUFOX_URL 变了，npm install 的缓存层依然有效。
# 同时，将下载、解压、设置权限合并到一层，减少层数。
ARG CAMOUFOX_URL
RUN curl -sSL ${CAMOUFOX_URL} -o camoufox-linux.tar.gz && \
    tar -xzf camoufox-linux.tar.gz && \
    rm camoufox-linux.tar.gz && \
    chmod +x /app/camoufox-linux/camoufox

# 4. [优化] 合并 COPY 指令，并将它们放在最后。
# 项目源代码是变化最频繁的，所以应该最后再拷贝进来。
COPY unified-server.js black-browser.js ./

# 5. [优化] 将目录操作合并到一层。
RUN mkdir ./auth && chown -R node:node ./auth /app/camoufox-linux

# 切换到非 root 用户
USER node

# 暴露服务端口
EXPOSE 7860
EXPOSE 9998

# 设置环境变量
ENV CAMOUFOX_EXECUTABLE_PATH=/app/camoufox-linux/camoufox

# 定义容器启动命令
CMD ["node", "unified-server.js"]
