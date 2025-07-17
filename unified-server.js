const express = require("express");
const WebSocket = require("ws");
const http = require("http");
const { EventEmitter } = require("events");
const fs = require("fs");
const path = require("path");
const { firefox } = require("playwright");
const os = require("os");

// ===================================================================================
// AUTH SOURCE MANAGEMENT MODULE
// ===================================================================================

class AuthSource {
  constructor(logger) {
    this.logger = logger;
    this.authMode = "file";
    this.availableIndices = [];
    this.initialIndices = []; // 新增：用于存储初步发现的所有索引

    if (process.env.AUTH_JSON_1) {
      this.authMode = "env";
      this.logger.info(
        "[Auth] 检测到 AUTH_JSON_1 环境变量，切换到环境变量认证模式。"
      );
    } else {
      this.logger.info(
        '[Auth] 未检测到环境变量认证，将使用 "auth/" 目录下的文件。'
      );
    }

    this._discoverAvailableIndices(); // 初步发现所有存在的源
    this._preValidateAndFilter(); // 预检验并过滤掉格式错误的源

    if (this.availableIndices.length === 0) {
      this.logger.error(
        `[Auth] 致命错误：在 '${this.authMode}' 模式下未找到任何有效的认证源。`
      );
      throw new Error("No valid authentication sources found.");
    }
  }

  _discoverAvailableIndices() {
    let indices = [];
    if (this.authMode === "env") {
      const regex = /^AUTH_JSON_(\d+)$/;
      // [关键修复] 完整的 for...in 循环，用于扫描所有环境变量
      for (const key in process.env) {
        const match = key.match(regex);
        if (match && match[1]) {
          indices.push(parseInt(match[1], 10));
        }
      }
    } else {
      // 'file' mode
      const authDir = path.join(__dirname, "auth");
      if (!fs.existsSync(authDir)) {
        this.logger.warn('[Auth] "auth/" 目录不存在。');
        this.availableIndices = [];
        return;
      }
      try {
        const files = fs.readdirSync(authDir);
        const authFiles = files.filter((file) => /^auth-\d+\.json$/.test(file));
        indices = authFiles.map((file) =>
          parseInt(file.match(/^auth-(\d+)\.json$/)[1], 10)
        );
      } catch (error) {
        this.logger.error(`[Auth] 扫描 "auth/" 目录失败: ${error.message}`);
        this.availableIndices = [];
        return;
      }
    }

    // 将扫描到的原始索引存起来
    this.initialIndices = [...new Set(indices)].sort((a, b) => a - b);
    this.availableIndices = [...this.initialIndices]; // 先假设都可用

    this.logger.info(
      `[Auth] 在 '${this.authMode}' 模式下，初步发现 ${
        this.initialIndices.length
      } 个认证源: [${this.initialIndices.join(", ")}]`
    );
  }

  _preValidateAndFilter() {
    if (this.availableIndices.length === 0) return;

    this.logger.info("[Auth] 开始预检验所有认证源的JSON格式...");
    const validIndices = [];
    const invalidSourceDescriptions = [];

    for (const index of this.availableIndices) {
      // 注意：这里我们调用一个内部的、简化的 getAuthContent
      const authContent = this._getAuthContent(index);
      if (authContent) {
        try {
          JSON.parse(authContent);
          validIndices.push(index);
        } catch (e) {
          invalidSourceDescriptions.push(`auth-${index}`);
        }
      } else {
        invalidSourceDescriptions.push(`auth-${index} (无法读取)`);
      }
    }

    if (invalidSourceDescriptions.length > 0) {
      this.logger.warn(
        `⚠️ [Auth] 预检验发现 ${
          invalidSourceDescriptions.length
        } 个格式错误或无法读取的认证源: [${invalidSourceDescriptions.join(
          ", "
        )}]，将从可用列表中移除。`
      );
    }

    this.availableIndices = validIndices;
  }

  // 一个内部辅助函数，仅用于预检验，避免日志污染
  _getAuthContent(index) {
    if (this.authMode === "env") {
      return process.env[`AUTH_JSON_${index}`];
    } else {
      const authFilePath = path.join(__dirname, "auth", `auth-${index}.json`);
      if (!fs.existsSync(authFilePath)) return null;
      try {
        return fs.readFileSync(authFilePath, "utf-8");
      } catch (e) {
        return null;
      }
    }
  }

  getAuth(index) {
    if (!this.availableIndices.includes(index)) {
      this.logger.error(`[Auth] 请求了无效或不存在的认证索引: ${index}`);
      return null;
    }

    let jsonString = this._getAuthContent(index);
    if (!jsonString) {
      this.logger.error(`[Auth] 在读取时无法获取认证源 #${index} 的内容。`);
      return null;
    }

    try {
      return JSON.parse(jsonString);
    } catch (e) {
      this.logger.error(
        `[Auth] 解析来自认证源 #${index} 的JSON内容失败: ${e.message}`
      );
      return null;
    }
  }
}
// ===================================================================================
// BROWSER MANAGEMENT MODULE
// ===================================================================================

class BrowserManager {
  constructor(logger, config, authSource) {
    this.logger = logger;
    this.config = config;
    this.authSource = authSource;
    this.browser = null;
    this.context = null;
    this.page = null;
    this.currentAuthIndex = 0;
    this.scriptFileName = "black-browser.js";

    if (this.config.browserExecutablePath) {
      this.browserExecutablePath = this.config.browserExecutablePath;
      this.logger.info(
        `[System] 使用环境变量 CAMOUFOX_EXECUTABLE_PATH 指定的浏览器路径。`
      );
    } else {
      const platform = os.platform();
      if (platform === "win32") {
        this.browserExecutablePath = path.join(
          __dirname,
          "camoufox",
          "camoufox.exe"
        );
        this.logger.info(
          `[System] 检测到操作系统: Windows. 将使用 'camoufox' 目录下的浏览器。`
        );
      } else if (platform === "linux") {
        this.browserExecutablePath = path.join(
          __dirname,
          "camoufox-linux",
          "camoufox"
        );
        this.logger.info(
          `[System] 检测到操作系统: Linux. 将使用 'camoufox-linux' 目录下的浏览器。`
        );
      } else {
        this.logger.error(`[System] 不支持的操作系统: ${platform}.`);
        throw new Error(`Unsupported operating system: ${platform}`);
      }
    }
  }

  async launchBrowser(authIndex) {
    if (this.browser) {
      this.logger.warn("尝试启动一个已在运行的浏览器实例，操作已取消。");
      return;
    }

    const sourceDescription =
      this.authSource.authMode === "env"
        ? `环境变量 AUTH_JSON_${authIndex}`
        : `文件 auth-${authIndex}.json`;
    this.logger.info("==================================================");
    this.logger.info(`🚀 [Browser] 准备启动浏览器`);
    this.logger.info(`   • 认证源: ${sourceDescription}`);
    this.logger.info(`   • 浏览器路径: ${this.browserExecutablePath}`);
    this.logger.info("==================================================");

    if (!fs.existsSync(this.browserExecutablePath)) {
      this.logger.error(
        `❌ [Browser] 找不到浏览器可执行文件: ${this.browserExecutablePath}`
      );
      throw new Error(
        `Browser executable not found at path: ${this.browserExecutablePath}`
      );
    }

    const storageStateObject = this.authSource.getAuth(authIndex);
    if (!storageStateObject) {
      this.logger.error(
        `❌ [Browser] 无法获取或解析索引为 ${authIndex} 的认证信息。`
      );
      throw new Error(
        `Failed to get or parse auth source for index ${authIndex}.`
      );
    }
    if (
      storageStateObject.cookies &&
      Array.isArray(storageStateObject.cookies)
    ) {
      let fixedCount = 0;
      const validSameSiteValues = ["Lax", "Strict", "None"];

      storageStateObject.cookies.forEach((cookie) => {
        // 检查 sameSite 的值是否在有效列表里
        if (!validSameSiteValues.includes(cookie.sameSite)) {
          // 如果无效 (比如是小写的 'lax', 空值, 或不存在), 则自动修正
          this.logger.warn(
            `[Auth] 发现无效的 Cookie sameSite 值: '${cookie.sameSite}'，正在自动修正为 'None'。`
          );
          cookie.sameSite = "None"; // 'None' 通常对于跨站嵌入的场景兼容性最好
          fixedCount++;
        }
      });

      if (fixedCount > 0) {
        this.logger.info(
          `[Auth] ✅ 自动修正了 ${fixedCount} 个无效的 Cookie 'sameSite' 属性。`
        );
      }
    }
    let buildScriptContent;
    try {
      const scriptFilePath = path.join(__dirname, this.scriptFileName);
      buildScriptContent = fs.readFileSync(scriptFilePath, "utf-8");
      this.logger.info(
        `✅ [Browser] 成功读取注入脚本 "${this.scriptFileName}"`
      );
    } catch (error) {
      this.logger.error(
        `❌ [Browser] 无法读取注入脚本 "${this.scriptFileName}"！`
      );
      throw error;
    }

    try {
      this.browser = await firefox.launch({
        headless: true,
        executablePath: this.browserExecutablePath,
      });
      this.browser.on("disconnected", () => {
        this.logger.error(
          "❌ [Browser] 浏览器意外断开连接！服务器可能需要重启。"
        );
        this.browser = null;
        this.context = null;
        this.page = null;
      });
      this.context = await this.browser.newContext({
        storageState: storageStateObject,
        viewport: { width: 1920, height: 1080 },
      });
      this.page = await this.context.newPage();
      this.page.on("console", (msg) => {
        const msgType = msg.type(); // 获取消息类型，如 'log', 'warn', 'error'
        const msgText = msg.text();

        // 核心过滤条件：我们只关心自己脚本产生的日志，它们的标志是包含"[ProxyClient]"
        if (msgText.includes("[ProxyClient]")) {
          // 为了美观，去掉浏览器脚本里的前缀，使用服务器的统一格式
          const cleanMsg = msgText.replace("[ProxyClient] ", "");
          // 根据浏览器日志的原始类型，决定在服务器上用什么级别打印
          if (msgType === "error" || msgType === "warn") {
            this.logger.warn(`[Browser] ${cleanMsg}`); // 用 WARN 级别打印浏览器的错误和警告
          } else {
            this.logger.info(`[Browser] ${cleanMsg}`); // 用 INFO 级别打印常规日志
          }
        }
        // 备用逻辑：如果一条消息不含我们的前缀，但它是一个错误(error)，我们可能也想看到它，以防页面本身崩溃
        else if (msgType === "error") {
          this.logger.error(`[Browser Page Error] ${msgText}`);
        }
      });
      this.logger.info(`[Browser] 正在加载账户 ${authIndex} 并访问目标网页...`);
      const targetUrl =
        "https://aistudio.google.com/u/0/apps/bundled/blank?showPreview=true&showCode=true&showAssistant=true";
      await this.page.goto(targetUrl, {
        timeout: 60000,
        waitUntil: "networkidle",
      });
      this.logger.info("[Browser] 检查登录状态...");
      // 尝试寻找一个只有在未登录时才会出现的元素，例如“Sign in”按钮
      // 注意：这里的选择器可能需要根据AI Studio页面的更新而调整
      const signInButton = this.page.locator(
        'a[href^="https://accounts.google.com/"]'
      );
      const isSignedIn = (await signInButton.count()) === 0;

      if (!isSignedIn) {
        // 如果找到了登录按钮，说明cookie无效，立即抛出错误
        throw new Error("Cookie无效或已过期，页面未处于登录状态。");
      }
      this.logger.info("[Browser] ✅ 登录状态正常。");
      this.logger.info("[Browser] 网页加载完成，正在注入客户端脚本...");

      const editorContainerLocator = this.page
        .locator("div.monaco-editor")
        .first();

      this.logger.info("[Browser] 等待编辑器出现，最长60秒...");
      await editorContainerLocator.waitFor({
        state: "visible",
        timeout: 60000,
      });
      this.logger.info("[Browser] 编辑器已出现，准备粘贴脚本。");

      await editorContainerLocator.click();
      await this.page.evaluate(
        (text) => navigator.clipboard.writeText(text),
        buildScriptContent
      );
      const isMac = os.platform() === "darwin";
      const pasteKey = isMac ? "Meta+V" : "Control+V";
      await this.page.keyboard.press(pasteKey);
      this.logger.info("[Browser] 脚本已粘贴。浏览器端初始化完成。");

      this.currentAuthIndex = authIndex;
      this.logger.info("==================================================");
      this.logger.info(`✅ [Browser] 账户 ${authIndex} 初始化成功！`);
      this.logger.info("✅ [Browser] 浏览器客户端已准备就绪。");
      this.logger.info("==================================================");
    } catch (error) {
      this.logger.error(
        `❌ [Browser] 账户 ${authIndex} 初始化失败: ${error.message}`
      );
      if (this.browser) {
        await this.browser.close();
        this.browser = null;
      }
      throw error;
    }
  }

  async closeBrowser() {
    if (this.browser) {
      this.logger.info("[Browser] 正在关闭当前浏览器实例...");
      await this.browser.close();
      this.browser = null;
      this.context = null;
      this.page = null;
      this.logger.info("[Browser] 浏览器已关闭。");
    }
  }

  async switchAccount(newAuthIndex) {
    this.logger.info(
      `🔄 [Browser] 开始账号切换: 从 ${this.currentAuthIndex} 到 ${newAuthIndex}`
    );
    await this.closeBrowser();
    await this.launchBrowser(newAuthIndex);
    this.logger.info(
      `✅ [Browser] 账号切换完成，当前账号: ${this.currentAuthIndex}`
    );
  }
}

// ===================================================================================
// PROXY SERVER MODULE
// ===================================================================================

class LoggingService {
  constructor(serviceName = "ProxyServer") {
    this.serviceName = serviceName;
    this.logBuffer = []; // 用于在内存中保存日志
    this.maxBufferSize = 100; // 最多保存100条
  }

  _formatMessage(level, message) {
    const timestamp = new Date().toISOString();
    const formatted = `[${level}] ${timestamp} [${this.serviceName}] - ${message}`;

    // 将格式化后的日志存入缓冲区
    this.logBuffer.push(formatted);
    // 如果缓冲区超过最大长度，则从头部删除旧的日志
    if (this.logBuffer.length > this.maxBufferSize) {
      this.logBuffer.shift();
    }

    return formatted;
  }

  info(message) {
    console.log(this._formatMessage("INFO", message));
  }
  error(message) {
    console.error(this._formatMessage("ERROR", message));
  }
  warn(message) {
    console.warn(this._formatMessage("WARN", message));
  }
  debug(message) {
    console.debug(this._formatMessage("DEBUG", message));
  }
}

class MessageQueue extends EventEmitter {
  constructor(timeoutMs = 600000) {
    super();
    this.messages = [];
    this.waitingResolvers = [];
    this.defaultTimeout = timeoutMs;
    this.closed = false;
  }
  enqueue(message) {
    if (this.closed) return;
    if (this.waitingResolvers.length > 0) {
      const resolver = this.waitingResolvers.shift();
      resolver.resolve(message);
    } else {
      this.messages.push(message);
    }
  }
  async dequeue(timeoutMs = this.defaultTimeout) {
    if (this.closed) {
      throw new Error("Queue is closed");
    }
    return new Promise((resolve, reject) => {
      if (this.messages.length > 0) {
        resolve(this.messages.shift());
        return;
      }
      const resolver = { resolve, reject };
      this.waitingResolvers.push(resolver);
      const timeoutId = setTimeout(() => {
        const index = this.waitingResolvers.indexOf(resolver);
        if (index !== -1) {
          this.waitingResolvers.splice(index, 1);
          reject(new Error("Queue timeout"));
        }
      }, timeoutMs);
      resolver.timeoutId = timeoutId;
    });
  }
  close() {
    this.closed = true;
    this.waitingResolvers.forEach((resolver) => {
      clearTimeout(resolver.timeoutId);
      resolver.reject(new Error("Queue closed"));
    });
    this.waitingResolvers = [];
    this.messages = [];
  }
}

class ConnectionRegistry extends EventEmitter {
  constructor(logger) {
    super();
    this.logger = logger;
    this.connections = new Set();
    this.messageQueues = new Map();
  }
  addConnection(websocket, clientInfo) {
    this.connections.add(websocket);
    this.logger.info(
      `[Server] 内部WebSocket客户端已连接 (来自: ${clientInfo.address})`
    );
    websocket.on("message", (data) =>
      this._handleIncomingMessage(data.toString())
    );
    websocket.on("close", () => this._removeConnection(websocket));
    websocket.on("error", (error) =>
      this.logger.error(`[Server] 内部WebSocket连接错误: ${error.message}`)
    );
    this.emit("connectionAdded", websocket);
  }
  _removeConnection(websocket) {
    this.connections.delete(websocket);
    this.logger.warn("[Server] 内部WebSocket客户端连接断开");
    this.messageQueues.forEach((queue) => queue.close());
    this.messageQueues.clear();
    this.emit("connectionRemoved", websocket);
  }
  _handleIncomingMessage(messageData) {
    try {
      const parsedMessage = JSON.parse(messageData);
      const requestId = parsedMessage.request_id;
      if (!requestId) {
        this.logger.warn("[Server] 收到无效消息：缺少request_id");
        return;
      }
      const queue = this.messageQueues.get(requestId);
      if (queue) {
        this._routeMessage(parsedMessage, queue);
      } else {
        this.logger.warn(`[Server] 收到未知请求ID的消息: ${requestId}`);
      }
    } catch (error) {
      this.logger.error("[Server] 解析内部WebSocket消息失败");
    }
  }
  _routeMessage(message, queue) {
    const { event_type } = message;
    switch (event_type) {
      case "response_headers":
      case "chunk":
      case "error":
        queue.enqueue(message);
        break;
      case "stream_close":
        queue.enqueue({ type: "STREAM_END" });
        break;
      default:
        this.logger.warn(`[Server] 未知的内部事件类型: ${event_type}`);
    }
  }
  hasActiveConnections() {
    return this.connections.size > 0;
  }
  getFirstConnection() {
    return this.connections.values().next().value;
  }
  createMessageQueue(requestId) {
    const queue = new MessageQueue();
    this.messageQueues.set(requestId, queue);
    return queue;
  }
  removeMessageQueue(requestId) {
    const queue = this.messageQueues.get(requestId);
    if (queue) {
      queue.close();
      this.messageQueues.delete(requestId);
    }
  }
}

class RequestHandler {
  constructor(
    serverSystem,
    connectionRegistry,
    logger,
    browserManager,
    config,
    authSource
  ) {
    this.serverSystem = serverSystem;
    this.connectionRegistry = connectionRegistry;
    this.logger = logger;
    this.browserManager = browserManager;
    this.config = config;
    this.authSource = authSource;
    this.maxRetries = this.config.maxRetries;
    this.retryDelay = this.config.retryDelay;
    this.failureCount = 0;
    this.usageCount = 0;
    this.isAuthSwitching = false;
    this.needsSwitchingAfterRequest = false;
  }

  get currentAuthIndex() {
    return this.browserManager.currentAuthIndex;
  }

  _getMaxAuthIndex() {
    return this.authSource.getMaxIndex();
  }

  _getNextAuthIndex() {
    const available = this.authSource.availableIndices; // 使用新的 availableIndices
    if (available.length === 0) return null;

    const currentIndexInArray = available.indexOf(this.currentAuthIndex);

    if (currentIndexInArray === -1) {
      this.logger.warn(
        `[Auth] 当前索引 ${this.currentAuthIndex} 不在可用列表中，将切换到第一个可用索引。`
      );
      return available[0];
    }

    const nextIndexInArray = (currentIndexInArray + 1) % available.length;
    return available[nextIndexInArray];
  }

  async _switchToNextAuth() {
    if (this.authSource.availableIndices.length <= 1) {
      this.logger.warn("[Auth] 😕 检测到只有一个可用账号，拒绝切换操作。");
      throw new Error("Only one account is available, cannot switch.");
    }

    if (this.isAuthSwitching) {
      this.logger.info("🔄 [Auth] 正在切换auth文件，跳过重复切换");
      return { success: false, reason: "Switch already in progress." }; // 返回一个状态
    }

    this.isAuthSwitching = true;
    const previousAuthIndex = this.currentAuthIndex;
    const nextAuthIndex = this._getNextAuthIndex();

    this.logger.info("==================================================");
    this.logger.info(`🔄 [Auth] 开始账号切换流程`);
    this.logger.info(`   • 当前账号: #${previousAuthIndex}`);
    this.logger.info(`   • 目标账号: #${nextAuthIndex}`);
    this.logger.info("==================================================");

    try {
      await this.browserManager.switchAccount(nextAuthIndex);
      this.failureCount = 0;
      this.usageCount = 0;
      this.logger.info(`✅ [Auth] 成功切换到账号 #${this.currentAuthIndex}`);
      // ...
      this.isAuthSwitching = false;
      return { success: true, newIndex: this.currentAuthIndex }; // 返回成功状态
    } catch (error) {
      this.logger.error(
        `❌ [Auth] 切换到账号 #${nextAuthIndex} 失败: ${error.message}`
      );
      this.logger.warn(
        `🚨 [Auth] 切换失败，正在尝试回退到上一个可用账号 #${previousAuthIndex}...`
      );
      try {
        await this.browserManager.launchBrowser(previousAuthIndex);
        this.logger.info(`✅ [Auth] 成功回退到账号 #${previousAuthIndex}！`);
        this.failureCount = 0;
        this.logger.info("[Auth] 失败计数已在回退成功后重置为0。");
        this.isAuthSwitching = false;
        return {
          success: false,
          fallback: true,
          newIndex: this.currentAuthIndex,
        }; // 返回回退成功状态
      } catch (fallbackError) {
        this.logger.error(
          `FATAL: ❌❌❌ [Auth] 紧急回退到账号 #${previousAuthIndex} 也失败了！`
        );
        // ...
        this.isAuthSwitching = false;
        throw fallbackError; // 如果连回退都失败了，就抛出最终错误
      }
    }
  }

  async _handleRequestFailureAndSwitch(errorDetails, res) {
    // 失败计数逻辑
    if (this.config.failureThreshold > 0) {
      this.failureCount++;
      this.logger.warn(
        `⚠️ [Auth] 请求失败 - 失败计数: ${this.failureCount}/${this.config.failureThreshold} (当前账号索引: ${this.currentAuthIndex})`
      );
    }

    const isImmediateSwitch = this.config.immediateSwitchStatusCodes.includes(
      errorDetails.status
    );
    const isThresholdReached =
      this.config.failureThreshold > 0 &&
      this.failureCount >= this.config.failureThreshold;

    // 只要满足任一切换条件
    if (isImmediateSwitch || isThresholdReached) {
      if (isImmediateSwitch) {
        this.logger.warn(
          `🔴 [Auth] 收到状态码 ${errorDetails.status}，触发立即切换账号...`
        );
      } else {
        this.logger.warn(
          `🔴 [Auth] 达到失败阈值 (${this.failureCount}/${this.config.failureThreshold})！准备切换账号...`
        );
      }

      // [核心修改] 等待切换操作完成，并根据其结果发送不同消息
      try {
        await this._switchToNextAuth();
        // 如果上面这行代码没有抛出错误，说明切换/回退成功了
        const successMessage = `🔄 目标账户无效，已自动回退至账号 #${this.currentAuthIndex}。`;
        this.logger.info(`[Auth] ${successMessage}`);
        if (res) this._sendErrorChunkToClient(res, successMessage);
      } catch (error) {
        let userMessage = `❌ 致命错误：发生未知切换错误: ${error.message}`;

        if (error.message.includes("Only one account is available")) {
          // 场景：单账号无法切换
          userMessage = "❌ 切换失败：只有一个可用账号。";
          this.logger.info("[Auth] 只有一个可用账号，失败计数已重置。");
          this.failureCount = 0;
        } else if (error.message.includes("回退失败原因")) {
          // 场景：切换到坏账号后，连回退都失败了
          userMessage = `❌ 致命错误：自动切换和紧急回退均失败，服务可能已中断，请检查日志！`;
        } else if (error.message.includes("切换到账号")) {
          // 场景：切换到坏账号后，成功回退（这是一个伪“成功”，本质是上一个操作失败了）
          userMessage = `⚠️ 自动切换失败：已自动回退到账号 #${this.currentAuthIndex}，请检查目标账号是否存在问题。`;
        }

        this.logger.error(`[Auth] 后台账号切换任务最终失败: ${error.message}`);
        if (res) this._sendErrorChunkToClient(res, userMessage);
      }

      return;
    }
  }

  async processRequest(req, res) {
    // ======================= 新增：切换状态检查 =======================
    // 1. 在处理任何事情之前，先检查是否有切换任务正在后台进行
    if (this.isAuthSwitching) {
      this.logger.warn(
        "[System] 收到新请求，但账号正在后台切换中，请稍后重试。"
      );
      // 返回一个明确的错误，告知客户端服务器正忙
      return this._sendErrorResponse(
        res,
        503,
        "服务暂时不可用：正在切换账号，请在几秒钟后重试。"
      );
    }
    // ===============================================================
    // 1. 将用量计数和检查逻辑，从finally块移动到这里
    // 确保在转发请求【之前】就完成计数和可能的切换
    if (this.config.switchOnUses > 0) {
      // 只要有请求意图，就将这次“尝试”计入用量
      this.usageCount++;
      this.logger.info(
        `[Request] 账号轮换计数: ${this.usageCount}/${this.config.switchOnUses} (当前账号: ${this.currentAuthIndex})`
      );

      // 检查用量是否【在本次使用后】达到或超过阈值
      if (this.usageCount >= this.config.switchOnUses) {
        // 注意：这里的切换将会在本次请求处理完毕后在后台进行
        // 我们先只记录一个标志，表明需要切换
        this.needsSwitchingAfterRequest = true;
      }
    }

    const requestId = this._generateRequestId();
    const proxyRequest = this._buildProxyRequest(req, requestId);
    const messageQueue = this.connectionRegistry.createMessageQueue(requestId);

    try {
      if (this.serverSystem.streamingMode === "fake") {
        await this._handlePseudoStreamResponse(
          proxyRequest,
          messageQueue,
          req,
          res
        );
      } else {
        await this._handleRealStreamResponse(proxyRequest, messageQueue, res);
      }
    } catch (error) {
      this._handleRequestError(error, res);
    } finally {
      this.connectionRegistry.removeMessageQueue(requestId);

      // ======================= 核心修改：事后切换逻辑 =======================
      // 2. 只有在本次请求成功完成后，才进行用量计数和切换检查
      // 在请求的所有流程都结束后，检查是否需要执行后台切换
      if (this.needsSwitchingAfterRequest) {
        this.logger.info(
          `[Auth] 轮换计数已达到切换阈值 (${this.usageCount}/${this.config.switchOnUses})，将在后台自动切换账号...`
        );
        this._switchToNextAuth().catch((err) => {
          this.logger.error(`[Auth] 后台账号切换任务失败: ${err.message}`);
        });
        this.needsSwitchingAfterRequest = false; // 重置标志
      }
    }
  } // =====================================================================

  _generateRequestId() {
    return `${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
  }
  _buildProxyRequest(req, requestId) {
    let requestBody = "";
    if (Buffer.isBuffer(req.body)) requestBody = req.body.toString("utf-8");
    else if (typeof req.body === "string") requestBody = req.body;
    else if (req.body) requestBody = JSON.stringify(req.body);
    return {
      path: req.path,
      method: req.method,
      headers: req.headers,
      query_params: req.query,
      body: requestBody,
      request_id: requestId,
      streaming_mode: this.serverSystem.streamingMode,
    };
  }
  _forwardRequest(proxyRequest) {
    const connection = this.connectionRegistry.getFirstConnection();
    if (connection) {
      connection.send(JSON.stringify(proxyRequest));
    } else {
      throw new Error("无法转发请求：没有可用的WebSocket连接。");
    }
  }
  _sendErrorChunkToClient(res, errorMessage) {
    const errorPayload = {
      error: {
        message: `[代理系统提示] ${errorMessage}`,
        type: "proxy_error",
        code: "proxy_error",
      },
    };
    const chunk = `data: ${JSON.stringify(errorPayload)}\n\n`;
    if (res && !res.writableEnded) {
      res.write(chunk);
      this.logger.info(`[Request] 已向客户端发送标准错误信号: ${errorMessage}`);
    }
  }

  async _handlePseudoStreamResponse(proxyRequest, messageQueue, req, res) {
    res.status(200).set({
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    this.logger.info("[Request] 已向客户端发送初始响应头。");

    // 发出请求，不再有服务器端的for循环重试
    this.logger.info(`[Request] 请求已派发给浏览器端处理...`);
    this._forwardRequest(proxyRequest);

    // 直接等待浏览器端的最终结果
    const headerMessage = await messageQueue.dequeue();

    // 如果浏览器直接返回错误
    if (headerMessage.event_type === "error") {
      await this._handleRequestFailureAndSwitch(headerMessage, res);
      this._sendErrorChunkToClient(
        res,
        `浏览器端报告错误: ${headerMessage.message}`
      );
      if (!res.writableEnded) res.end();
      return;
    }

    // 正常处理成功的响应
    if (this.failureCount > 0) {
      this.logger.info(
        `✅ [Auth] 请求成功 - 失败计数已从 ${this.failureCount} 重置为 0`
      );
    }
    this.failureCount = 0;

    const dataMessage = await messageQueue.dequeue();
    const endMessage = await messageQueue.dequeue();

    if (dataMessage.data) {
      res.write(`data: ${dataMessage.data}\n\n`);
      this.logger.info("[Request] 已将完整响应体作为SSE事件发送。");
    }
    if (endMessage.type !== "STREAM_END")
      this.logger.warn("[Request] 未收到预期的流结束信号。");

    if (!res.writableEnded) res.end();
    this.logger.info("[Request] 假流式响应处理结束。");
  }

  async _handleRealStreamResponse(proxyRequest, messageQueue, res) {
    // 发出请求，不再有服务器端的for循环重试
    this.logger.info(`[Request] 请求已派发给浏览器端处理...`);
    this._forwardRequest(proxyRequest);

    // 直接等待浏览器端的最终结果
    const headerMessage = await messageQueue.dequeue();

    // 如果浏览器直接返回错误
    if (headerMessage.event_type === "error") {
      await this._handleRequestFailureAndSwitch(headerMessage, null);
      return this._sendErrorResponse(
        res,
        headerMessage.status,
        headerMessage.message
      );
    }

    // 正常处理成功的响应
    if (this.failureCount > 0) {
      this.logger.info(
        `✅ [Auth] 请求成功 - 失败计数已从 ${this.failureCount} 重置为 0`
      );
    }
    this.failureCount = 0;
    this._setResponseHeaders(res, headerMessage);

    this.logger.info("[Request] 已向客户端发送真实响应头，开始流式传输...");
    try {
      while (true) {
        const dataMessage = await messageQueue.dequeue(30000);
        if (dataMessage.type === "STREAM_END") {
          this.logger.info("[Request] 收到流结束信号。");
          break;
        }
        if (dataMessage.data) res.write(dataMessage.data);
      }
    } catch (error) {
      if (error.message !== "Queue timeout") throw error;
      this.logger.warn("[Request] 真流式响应超时，可能流已正常结束。");
    } finally {
      if (!res.writableEnded) res.end();
      this.logger.info("[Request] 真流式响应连接已关闭。");
    }
  }

  _getKeepAliveChunk(req) {
    if (req.path.includes("chat/completions")) {
      const payload = {
        id: `chatcmpl-${this._generateRequestId()}`,
        object: "chat.completion.chunk",
        created: Math.floor(Date.now() / 1000),
        model: "gpt-4",
        choices: [{ index: 0, delta: {}, finish_reason: null }],
      };
      return `data: ${JSON.stringify(payload)}\n\n`;
    }
    if (
      req.path.includes("generateContent") ||
      req.path.includes("streamGenerateContent")
    ) {
      const payload = {
        candidates: [
          {
            content: { parts: [{ text: "" }], role: "model" },
            finishReason: null,
            index: 0,
            safetyRatings: [],
          },
        ],
      };
      return `data: ${JSON.stringify(payload)}\n\n`;
    }
    return "data: {}\n\n";
  }
  _setResponseHeaders(res, headerMessage) {
    res.status(headerMessage.status || 200);
    const headers = headerMessage.headers || {};
    Object.entries(headers).forEach(([name, value]) => {
      if (name.toLowerCase() !== "content-length") res.set(name, value);
    });
  }
  _handleRequestError(error, res) {
    if (res.headersSent) {
      this.logger.error(`[Request] 请求处理错误 (头已发送): ${error.message}`);
      if (this.serverSystem.streamingMode === "fake")
        this._sendErrorChunkToClient(res, `处理失败: ${error.message}`);
      if (!res.writableEnded) res.end();
    } else {
      this.logger.error(`[Request] 请求处理错误: ${error.message}`);
      const status = error.message.includes("超时") ? 504 : 500;
      this._sendErrorResponse(res, status, `代理错误: ${error.message}`);
    }
  }

  _sendErrorResponse(res, status, message) {
    if (!res.headersSent) {
      // 1. 创建一个符合API规范的JSON错误对象
      const errorPayload = {
        error: {
          code: status || 500,
          message: message,
          status: "SERVICE_UNAVAILABLE", // 这是一个示例状态名
        },
      };
      // 2. 设置响应类型为 application/json 并发送
      res
        .status(status || 500)
        .type("application/json")
        .send(JSON.stringify(errorPayload));
    }
  }
}

class ProxyServerSystem extends EventEmitter {
  constructor() {
    super();
    this.logger = new LoggingService("ProxySystem");
    this._loadConfiguration(); // 这个函数会执行下面的_loadConfiguration
    this.streamingMode = this.config.streamingMode;

    this.authSource = new AuthSource(this.logger);
    this.browserManager = new BrowserManager(
      this.logger,
      this.config,
      this.authSource
    );
    this.connectionRegistry = new ConnectionRegistry(this.logger);
    this.requestHandler = new RequestHandler(
      this,
      this.connectionRegistry,
      this.logger,
      this.browserManager,
      this.config,
      this.authSource
    );

    this.httpServer = null;
    this.wsServer = null;
  }

  // ===== 所有函数都已正确放置在类内部 =====

  _loadConfiguration() {
    let config = {
      httpPort: 7860,
      host: "0.0.0.0",
      wsPort: 9998,
      streamingMode: "fake",
      failureThreshold: 3,
      switchOnUses: 40,
      maxRetries: 1,
      retryDelay: 2000,
      browserExecutablePath: null,
      apiKeys: [],
      immediateSwitchStatusCodes: [],
    };

    const configPath = path.join(__dirname, "config.json");
    try {
      if (fs.existsSync(configPath)) {
        const fileConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
        config = { ...config, ...fileConfig };
        this.logger.info("[System] 已从 config.json 加载配置。");
      }
    } catch (error) {
      this.logger.warn(`[System] 无法读取或解析 config.json: ${error.message}`);
    }

    if (process.env.PORT)
      config.httpPort = parseInt(process.env.PORT, 10) || config.httpPort;
    if (process.env.HOST) config.host = process.env.HOST;
    if (process.env.STREAMING_MODE)
      config.streamingMode = process.env.STREAMING_MODE;
    if (process.env.FAILURE_THRESHOLD)
      config.failureThreshold =
        parseInt(process.env.FAILURE_THRESHOLD, 10) || config.failureThreshold;
    if (process.env.SWITCH_ON_USES)
      config.switchOnUses =
        parseInt(process.env.SWITCH_ON_USES, 10) || config.switchOnUses;
    if (process.env.MAX_RETRIES)
      config.maxRetries =
        parseInt(process.env.MAX_RETRIES, 10) || config.maxRetries;
    if (process.env.RETRY_DELAY)
      config.retryDelay =
        parseInt(process.env.RETRY_DELAY, 10) || config.retryDelay;
    if (process.env.CAMOUFOX_EXECUTABLE_PATH)
      config.browserExecutablePath = process.env.CAMOUFOX_EXECUTABLE_PATH;
    if (process.env.API_KEYS) {
      config.apiKeys = process.env.API_KEYS.split(",");
    }

    let rawCodes = process.env.IMMEDIATE_SWITCH_STATUS_CODES;
    let codesSource = "环境变量";

    if (
      !rawCodes &&
      config.immediateSwitchStatusCodes &&
      Array.isArray(config.immediateSwitchStatusCodes)
    ) {
      rawCodes = config.immediateSwitchStatusCodes.join(",");
      codesSource = "config.json 文件";
    }

    if (rawCodes && typeof rawCodes === "string") {
      config.immediateSwitchStatusCodes = rawCodes
        .split(",")
        .map((code) => parseInt(String(code).trim(), 10))
        .filter((code) => !isNaN(code) && code >= 400 && code <= 599);
      if (config.immediateSwitchStatusCodes.length > 0) {
        this.logger.info(`[System] 已从 ${codesSource} 加载“立即切换报错码”。`);
      }
    } else {
      config.immediateSwitchStatusCodes = [];
    }

    if (Array.isArray(config.apiKeys)) {
      config.apiKeys = config.apiKeys
        .map((k) => String(k).trim())
        .filter((k) => k);
    } else {
      config.apiKeys = [];
    }

    this.config = config;
    this.logger.info("================ [ 生效配置 ] ================");
    this.logger.info(`  HTTP 服务端口: ${this.config.httpPort}`);
    this.logger.info(`  监听地址: ${this.config.host}`);
    this.logger.info(`  流式模式: ${this.config.streamingMode}`);
    this.logger.info(
      `  轮换计数切换阈值: ${
        this.config.switchOnUses > 0
          ? `每 ${this.config.switchOnUses} 次请求后切换`
          : "已禁用"
      }`
    );
    this.logger.info(
      `  失败计数切换: ${
        this.config.failureThreshold > 0
          ? `失败${this.config.failureThreshold} 次后切换`
          : "已禁用"
      }`
    );
    this.logger.info(
      `  立即切换报错码: ${
        this.config.immediateSwitchStatusCodes.length > 0
          ? this.config.immediateSwitchStatusCodes.join(", ")
          : "已禁用"
      }`
    );
    this.logger.info(`  单次请求最大重试: ${this.config.maxRetries}次`);
    this.logger.info(`  重试间隔: ${this.config.retryDelay}ms`);
    if (this.config.apiKeys && this.config.apiKeys.length > 0) {
      this.logger.info(
        `  API 密钥认证: 已启用 (${this.config.apiKeys.length} 个密钥)`
      );
    } else {
      this.logger.info(`  API 密钥认证: 已禁用`);
    }
    this.logger.info(
      "============================================================="
    );
  }

  async start() {
    this.logger.info(
      "[System] 开始弹性启动流程，将尝试所有可用账号直到成功..."
    );
    const availableIndices = this.authSource.availableIndices;

    if (availableIndices.length === 0) {
      // 这个情况在AuthSource的构造函数里已经处理了，但为了保险再次检查
      throw new Error("没有任何可用的认证源，无法启动。");
    }

    let isStarted = false;
    for (const index of availableIndices) {
      try {
        this.logger.info(`[System] 尝试使用账号 #${index} 启动服务...`);
        await this.browserManager.launchBrowser(index);
        // 如果 aunchBrowser 没有抛出错误，说明启动成功
        isStarted = true;
        this.logger.info(`[System] ✅ 使用账号 #${index} 成功启动！`);
        break; // 成功启动，跳出循环
      } catch (error) {
        this.logger.error(
          `[System] ❌ 使用账号 #${index} 启动失败。原因: ${error.message}`
        );
        // 失败了，循环将继续，尝试下一个账号
      }
    }

    if (!isStarted) {
      // 如果所有账号都尝试失败了
      throw new Error("所有认证源均尝试失败，服务器无法启动。");
    }

    // 只有在浏览器成功启动后，才启动网络服务
    await this._startHttpServer();
    await this._startWebSocketServer();
    this.logger.info(`[System] 代理服务器系统启动完成。`);
    this.emit("started");
  }

  _createAuthMiddleware() {
    const basicAuth = require("basic-auth"); // 确保此行存在，为admin认证提供支持

    return (req, res, next) => {
      const serverApiKeys = this.config.apiKeys;
      if (!serverApiKeys || serverApiKeys.length === 0) {
        return next();
      }

      let clientKey = null;
      if (req.headers["x-goog-api-key"]) {
        clientKey = req.headers["x-goog-api-key"];
      } else if (
        req.headers.authorization &&
        req.headers.authorization.startsWith("Bearer ")
      ) {
        clientKey = req.headers.authorization.substring(7);
      } else if (req.headers["x-api-key"]) {
        clientKey = req.headers["x-api-key"];
      } else if (req.query.key) {
        clientKey = req.query.key;
      }

      if (clientKey && serverApiKeys.includes(clientKey)) {
        this.logger.info(
          `[Auth] API Key验证通过 (来自: ${
            req.headers["x-forwarded-for"] || req.ip
          })`
        );
        if (req.query.key) {
          delete req.query.key;
        }
        return next();
      }

      // 对于没有有效API Key的请求，返回401错误
      // 注意：健康检查等逻辑已在_createExpressApp中提前处理
      const clientIp = req.headers["x-forwarded-for"] || req.ip;
      this.logger.warn(
        `[Auth] 访问密码错误或缺失，已拒绝请求。IP: ${clientIp}, Path: ${req.path}`
      );
      return res.status(401).json({
        error: {
          message:
            "Access denied. A valid API key was not found or is incorrect.",
        },
      });
    };
  }

  async _startHttpServer() {
    const app = this._createExpressApp();
    this.httpServer = http.createServer(app);
    return new Promise((resolve) => {
      this.httpServer.listen(this.config.httpPort, this.config.host, () => {
        this.logger.info(
          `[System] HTTP服务器已在 http://${this.config.host}:${this.config.httpPort} 上监听`
        );
        resolve();
      });
    });
  }

  _createExpressApp() {
    const app = express();
    const basicAuth = require("basic-auth");

    app.use(express.json({ limit: "100mb" }));
    app.use(express.raw({ type: "*/*", limit: "100mb" }));

    const adminAuth = (req, res, next) => {
      const credentials = basicAuth(req);
      const serverApiKey =
        (this.config.apiKeys && this.config.apiKeys[0]) || null;
      if (
        !credentials ||
        credentials.name !== "root" ||
        credentials.pass !== serverApiKey
      ) {
        res.setHeader("WWW-Authenticate", 'Basic realm="Admin Area"');
        return res.status(401).send("Authentication required.");
      }
      return next();
    };

    // 1. 处理公开路径和健康检查 (在所有认证之前)
    // ==================== 用这个包含“状态”+“日志”的最终版本进行完整替换 ====================

    app.get("/", (req, res) => {
      // 健康检查逻辑保持不变
      const remoteIp = req.ip;
      const userAgent = req.headers["user-agent"] || "";
      const isHealthCheck =
        remoteIp &&
        remoteIp.startsWith("10.") &&
        !userAgent.includes("Mozilla");
      if (isHealthCheck) {
        return res.status(200).send("Health check OK.");
      }

      // 获取数据的逻辑保持不变
      const { config, requestHandler, authSource, browserManager } = this;
      const initialIndices = authSource.initialIndices || [];
      const availableIndices = authSource.availableIndices || [];
      const invalidIndices = initialIndices.filter(
        (i) => !availableIndices.includes(i)
      );
      const logs = this.logger.logBuffer || [];

      // 构建HTML响应，注意 <head> 部分的变化
      const statusHtml = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>代理服务状态</title>
          <style>
            body { font-family: 'SF Mono', 'Consolas', 'Menlo', monospace; background-color: #f0f2f5; color: #333; padding: 2em; }
            .container { max-width: 800px; margin: 0 auto; background: #fff; padding: 1em 2em 2em 2em; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            h1, h2 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 0.5em;}
            pre { background: #2d2d2d; color: #f0f0f0; font-size: 1.1em; padding: 1.5em; border-radius: 8px; white-space: pre-wrap; word-wrap: break-word; line-height: 1.6; }
            #log-container { font-size: 0.9em; max-height: 400px; overflow-y: auto; }
            .status-ok { color: #2ecc71; font-weight: bold; }
            .status-error { color: #e74c3c; font-weight: bold; }
            .label { display: inline-block; width: 220px; }
            .dot { height: 10px; width: 10px; background-color: #bbb; border-radius: 50%; display: inline-block; margin-left: 10px; animation: blink 1s infinite alternate; }
            @keyframes blink { from { opacity: 0.3; } to { opacity: 1; } }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>代理服务状态 <span class="dot" title="数据动态刷新中..."></span></h1>
            <div id="status-section">
              <pre>
<span class="label">服务状态</span>: <span class="status-ok">Running</span>
--- 服务配置 ---
<span class="label">流式模式</span>: ${config.streamingMode}
<span class="label">次数轮换</span>: ${
        config.switchOnUses > 0 ? `每 ${config.switchOnUses} 次` : "已禁用"
      }
<span class="label">失败切换</span>: ${
        config.failureThreshold > 0
          ? `失败 ${config.failureThreshold} 次后切换`
          : "已禁用"
      }
<span class="label">立即切换 (状态码)</span>: ${
        config.immediateSwitchStatusCodes.length > 0
          ? `[${config.immediateSwitchStatusCodes.join(", ")}]`
          : "已禁用"
      }
--- 账号状态 ---
<span class="label">扫描到的总账号</span>: [${initialIndices.join(
        ", "
      )}] (总数: ${initialIndices.length})
<span class="label">格式正确 (可用)</span>: [${availableIndices.join(
        ", "
      )}] (总数: ${availableIndices.length})
<span class="label">格式错误 (已忽略)</span>: [${invalidIndices.join(
        ", "
      )}] (总数: ${invalidIndices.length})
<span class="label">当前使用账号</span>: #${requestHandler.currentAuthIndex}
<span class="label">使用次数计数</span>: ${requestHandler.usageCount} / ${
        config.switchOnUses > 0 ? config.switchOnUses : "N/A"
      }
<span class="label">连续失败计数</span>: ${requestHandler.failureCount} / ${
        config.failureThreshold > 0 ? config.failureThreshold : "N/A"
      }
--- 连接状态 ---
<span class="label">浏览器连接</span>: <span class="${
        browserManager.browser ? "status-ok" : "status-error"
      }">${!!browserManager.browser}</span>
              </pre>
            </div>
            <div id="log-section">
              <h2>实时日志 (最近 ${logs.length} 条)</h2>
              <pre id="log-container">${logs.join("\n")}</pre>
            </div>
          </div>

          <script>
            function updateContent() {
              fetch('/')
                .then(response => response.text())
                .then(html => {
                  const parser = new DOMParser();
                  const doc = parser.parseFromString(html, 'text/html');

                  const newStatus = doc.getElementById('status-section').innerHTML;
                  const newLogs = doc.getElementById('log-section').innerHTML;
                  
                  const logContainer = document.getElementById('log-container');
                  const isScrolledToBottom = logContainer.scrollHeight - logContainer.clientHeight <= logContainer.scrollTop + 1;

                  document.getElementById('status-section').innerHTML = newStatus;
                  document.getElementById('log-section').innerHTML = newLogs;

                  if(isScrolledToBottom) {
                    const newLogContainer = document.getElementById('log-container');
                    newLogContainer.scrollTop = newLogContainer.scrollHeight;
                  }
                })
                .catch(error => console.error('Error fetching new content:', error));
            }
            setInterval(updateContent, 5000); // 每5秒执行一次软刷新
          </script>
        </body>
        </html>
      `;

      res.status(200).send(statusHtml);
    });

    app.get("/favicon.ico", (req, res) => res.status(204).send());
    // 2. 保护管理路径
    app.use("/admin", adminAuth);
    app.get("/admin/set-mode", (req, res) => {
      const newMode = req.query.mode;
      if (newMode === "fake" || newMode === "real") {
        this.streamingMode = newMode;
        this.logger.info(
          `[Admin] 流式模式已由认证用户切换为: ${this.streamingMode}`
        );
        res.status(200).send(`流式模式已切换为: ${this.streamingMode}`);
      } else {
        res.status(400).send('无效模式. 请用 "fake" 或 "real".');
      }
    });

    app.get("/admin/switch", async (req, res) => {
      this.logger.info("[Admin] 收到手动切换账号请求...");

      if (this.authSource.availableIndices.length <= 1) {
        const userMessage = "⚠️ 切换操作已取消：只有一个可用账号，无法切换。";
        this.logger.warn(`[Admin] ${userMessage}`);
        return res.status(400).send(userMessage);
      }

      const currentAuth = this.requestHandler.currentAuthIndex;

      try {
        const result = await this.requestHandler._switchToNextAuth();

        if (result.success) {
          const message = `✅ 手动切换成功！已从账号 ${currentAuth} 切换到账号 ${result.newIndex}。`;
          this.logger.info(`[Admin] ${message}`);
          res.status(200).send(message);
        } else if (result.fallback) {
          const message = `⚠️ 切换失败，但已成功回退到账号 #${result.newIndex}。请检查目标账号是否存在问题。`;
          this.logger.warn(`[Admin] ${message}`);
          res.status(200).send(message);
        } else {
          res.status(409).send(`操作未执行: ${result.reason}`);
        }
      } catch (error) {
        const message = `❌ 致命错误：切换和回退均失败，服务可能已中断！错误: ${error.message}`;
        this.logger.error(`[Admin] ${message}`);
        res.status(500).send(message);
      }
    });

    // 3. 保护所有其他API路径
    app.use(this._createAuthMiddleware());
    app.all(/(.*)/, (req, res) => {
      // [关键修复] 原本在这里的 if 判断已提到前面，这里不再需要
      this.requestHandler.processRequest(req, res);
    });

    return app;
  }

  async _startWebSocketServer() {
    this.wsServer = new WebSocket.Server({
      port: this.config.wsPort,
      host: this.config.host,
    });
    this.wsServer.on("connection", (ws, req) => {
      this.connectionRegistry.addConnection(ws, {
        address: req.socket.remoteAddress,
      });
    });
  }
}

// ===================================================================================
// MAIN INITIALIZATION
// ===================================================================================

async function initializeServer() {
  const initialAuthIndex = parseInt(process.env.INITIAL_AUTH_INDEX, 10) || 1;
  try {
    const serverSystem = new ProxyServerSystem();
    await serverSystem.start(initialAuthIndex);
  } catch (error) {
    console.error("❌ 服务器启动失败:", error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  initializeServer();
}

module.exports = { ProxyServerSystem, BrowserManager, initializeServer };
