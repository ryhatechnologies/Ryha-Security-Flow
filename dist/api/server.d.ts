declare class RyhaServer {
    private app;
    private server;
    private io;
    private port;
    private orchestrator;
    private toolManager;
    private authValidator;
    private terminalLog;
    private terminalId;
    private activeJobId;
    constructor(port?: number);
    private addTerminalEntry;
    private setupOrchestratorEvents;
    private setupMiddleware;
    private setupRoutes;
    private setupSocketIO;
    start(): void;
}
export { RyhaServer };
//# sourceMappingURL=server.d.ts.map