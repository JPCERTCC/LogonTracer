class AISecurityAssistant {
    constructor() {
        this.isAnalyzing = false;
        this.currentAnalysis = null;
        this.isEnabled = false;
        this.analysisPanel = null;
        this.agentRunning = false;
        this.currentAgentJobId = null;
        this.hitlSession = null;

        // Initialize panel after ensuring DOM is ready
        this.initializePanel();

        // Check LLM status on initialization
        this.checkAIStatus();
    }

    getCsrfToken() {
        return document.cookie.split(';')
            .map(c => c.trim())
            .find(c => c.startsWith('csrf_token='))
            ?.split('=')[1] || '';
    }

    escapeHtml(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    initializePanel() {
        // Ensure document.body exists
        if (!document.body) {
            console.warn('Document body not ready, delaying panel creation');
            setTimeout(() => this.initializePanel(), 100);
            return;
        }
        
        this.analysisPanel = this.createAnalysisPanel();
    }

    async checkAIStatus() {
        try {
            const response = await fetch('/api/ai-status');
            const result = await response.json();
            
            if (result.success && result.status.enabled) {
                this.isEnabled = true;
                console.log('AI Analysis Assistant enabled:', result.status);
            } else {
                this.isEnabled = false;
                console.log('AI Analysis Assistant disabled:', result.status);
            }
        } catch (error) {
            console.warn('AI Analysis Assistant not available:', error);
            this.isEnabled = false;
        }
    }

    createAnalysisPanel() {
        const panel = document.createElement('div');
        panel.id = 'ai-analysis-panel';
        panel.className = 'ai-analysis-panel';
        panel.style.cssText = `
            position: fixed;
            top: 80px;
            right: 20px;
            width: 420px;
            max-height: 600px;
            min-width: 300px;
            min-height: 200px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 1000;
            display: none;
            overflow-y: hidden;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            resize: both;
        `;
        
        panel.innerHTML = `
            <div class="panel-header" style="padding: 15px; border-bottom: 1px solid #eee; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px 8px 0 0; color: white; cursor: move; user-select: none;">
                <h5 style="margin: 0; display: flex; align-items: center; font-weight: 600;">
                    <i class="fas fa-brain" style="margin-right: 8px; color: #fff;"></i>
                    AI Analysis
                    <button id="panel-resize-btn" onclick="aiAssistant.togglePanelSize()" 
                            style="margin-left: auto; margin-right: 10px; border: 1px solid rgba(255,255,255,0.3); background: rgba(255,255,255,0.1); font-size: 12px; cursor: pointer; color: white; opacity: 0.8; padding: 4px 8px; border-radius: 4px;"
                            onmouseover="this.style.opacity='1'; this.style.background='rgba(255,255,255,0.2)'" 
                            onmouseout="this.style.opacity='0.8'; this.style.background='rgba(255,255,255,0.1)'"
                            title="Toggle panel size">
                        <i class="fas fa-expand-arrows-alt"></i>
                    </button>
                    <button id="show-history-btn" onclick="aiAssistant.showLastAnalysis()" 
                            style="margin-right: 10px; border: 1px solid rgba(255,255,255,0.3); background: rgba(255,255,255,0.1); font-size: 12px; cursor: pointer; color: white; opacity: 0.8; padding: 4px 8px; border-radius: 4px; display: none;"
                            onmouseover="this.style.opacity='1'; this.style.background='rgba(255,255,255,0.2)'" 
                            onmouseout="this.style.opacity='0.8'; this.style.background='rgba(255,255,255,0.1)'">
                        <i class="fas fa-history" style="margin-right: 4px;"></i>Last Result
                    </button>
                    <button class="btn-close" onclick="hideAIPanel()" 
                            style="border: none; background: none; font-size: 20px; cursor: pointer; color: white; opacity: 0.8;"
                            onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0.8'">&times;</button>
                </h5>
                <small style="opacity: 0.9; font-size: 12px;">Powered by configured LLM provider</small>
            </div>
            <div class="panel-body" id="analysis-content" style="padding: 15px; height: calc(100% - 80px); overflow-y: auto;">
                <div class="loading-indicator" style="text-align: center; padding: 20px;">
                    <i class="fas fa-spinner fa-spin" style="font-size: 24px; color: #667eea;"></i>
                    <p style="margin-top: 10px; color: #666; font-size: 14px;">Analyzing security patterns...</p>
                </div>
            </div>
            <!-- Resize handles -->
            <div class="resize-handle-corner" style="position: absolute; bottom: 0; left: 0; width: 20px; height: 20px; cursor: ne-resize; background: linear-gradient(45deg, transparent 30%, rgba(102, 126, 234, 0.3) 30%, rgba(102, 126, 234, 0.3) 70%, transparent 70%);"></div>
            <div class="resize-handle-right-corner" style="position: absolute; bottom: 0; right: 0; width: 20px; height: 20px; cursor: nw-resize; background: linear-gradient(-45deg, transparent 30%, rgba(102, 126, 234, 0.3) 30%, rgba(102, 126, 234, 0.3) 70%, transparent 70%);"></div>
            <div class="resize-handle-left" style="position: absolute; top: 0; left: 0; width: 5px; height: 100%; cursor: ew-resize; background: transparent;"></div>
            <div class="resize-handle-right" style="position: absolute; top: 0; right: 0; width: 5px; height: 100%; cursor: ew-resize; background: transparent;"></div>
            <div class="resize-handle-bottom" style="position: absolute; bottom: 0; left: 0; width: 100%; height: 5px; cursor: ns-resize; background: transparent;"></div>
        `;
        
        document.body.appendChild(panel);
        
        // Add drag functionality
        this.makePanelDraggable(panel);
        
        // Add resize functionality
        this.makePanelResizable(panel);
        
        // Initialize history button visibility
        setTimeout(() => this.updateHistoryButtonVisibility(), 100);
        
        return panel;
    }

    makePanelDraggable(panel) {
        const header = panel.querySelector('.panel-header');
        let isDragging = false;
        let currentX;
        let currentY;
        let initialX;
        let initialY;
        let xOffset = 0;
        let yOffset = 0;

        header.addEventListener('mousedown', (e) => {
            // Don't drag if clicking on buttons
            if (e.target.tagName === 'BUTTON' || e.target.tagName === 'I') return;
            
            initialX = e.clientX - xOffset;
            initialY = e.clientY - yOffset;

            if (e.target === header || header.contains(e.target)) {
                isDragging = true;
                header.style.cursor = 'grabbing';
            }
        });

        document.addEventListener('mousemove', (e) => {
            if (isDragging) {
                e.preventDefault();
                currentX = e.clientX - initialX;
                currentY = e.clientY - initialY;

                xOffset = currentX;
                yOffset = currentY;

                // Constrain to viewport
                const rect = panel.getBoundingClientRect();
                const maxX = window.innerWidth - rect.width;
                const maxY = window.innerHeight - rect.height;
                
                xOffset = Math.max(0, Math.min(maxX, xOffset));
                yOffset = Math.max(0, Math.min(maxY, yOffset));

                panel.style.transform = `translate(${xOffset}px, ${yOffset}px)`;
            }
        });

        document.addEventListener('mouseup', () => {
            if (isDragging) {
                isDragging = false;
                header.style.cursor = 'move';
            }
        });
    }

    makePanelResizable(panel) {
        const cornerHandle = panel.querySelector('.resize-handle-corner');
        const rightCornerHandle = panel.querySelector('.resize-handle-right-corner');
        const leftHandle = panel.querySelector('.resize-handle-left');
        const rightHandle = panel.querySelector('.resize-handle-right');
        const bottomHandle = panel.querySelector('.resize-handle-bottom');
        
        let isResizing = false;
        let resizeType = '';
        let startX, startY, startWidth, startHeight, startLeft;

        const startResize = (e, type) => {
            isResizing = true;
            resizeType = type;
            startX = e.clientX;
            startY = e.clientY;
            startWidth = parseInt(document.defaultView.getComputedStyle(panel).width, 10);
            startHeight = parseInt(document.defaultView.getComputedStyle(panel).height, 10);
            startLeft = panel.offsetLeft;
            e.preventDefault();
        };

        cornerHandle.addEventListener('mousedown', (e) => startResize(e, 'left-corner'));
        rightCornerHandle.addEventListener('mousedown', (e) => startResize(e, 'right-corner'));
        leftHandle.addEventListener('mousedown', (e) => startResize(e, 'left'));
        rightHandle.addEventListener('mousedown', (e) => startResize(e, 'right'));
        bottomHandle.addEventListener('mousedown', (e) => startResize(e, 'bottom'));

        document.addEventListener('mousemove', (e) => {
            if (!isResizing) return;

            const dx = e.clientX - startX;
            const dy = e.clientY - startY;

            // Left corner and left edge resizing (shrink width from left)
            if (resizeType === 'left-corner' || resizeType === 'left') {
                const newWidth = Math.max(300, Math.min(window.innerWidth - 40, startWidth - dx));
                const newLeft = Math.max(0, Math.min(window.innerWidth - newWidth, startLeft + dx));
                panel.style.width = newWidth + 'px';
                panel.style.left = newLeft + 'px';
            }

            // Right corner and right edge resizing (expand width from right)
            if (resizeType === 'right-corner' || resizeType === 'right') {
                const newWidth = Math.max(300, Math.min(window.innerWidth - 40, startWidth + dx));
                panel.style.width = newWidth + 'px';
            }

            // Bottom resizing (both corners and bottom edge)
            if (resizeType === 'left-corner' || resizeType === 'right-corner' || resizeType === 'bottom') {
                const newHeight = Math.max(200, Math.min(window.innerHeight - 100, startHeight + dy));
                panel.style.height = newHeight + 'px';
                panel.style.maxHeight = newHeight + 'px';
            }
        });

        document.addEventListener('mouseup', () => {
            isResizing = false;
            resizeType = '';
        });
    }

    togglePanelSize() {
        if (!this.analysisPanel) return;
        
        const panel = this.analysisPanel;
        const isMaximized = panel.classList.contains('maximized');
        
        if (isMaximized) {
            // Restore to normal size
            panel.classList.remove('maximized');
            panel.style.width = panel.dataset.originalWidth || '420px';
            panel.style.height = panel.dataset.originalHeight || 'auto';
            panel.style.maxHeight = panel.dataset.originalMaxHeight || '600px';
            panel.style.top = panel.dataset.originalTop || '80px';
            panel.style.left = panel.dataset.originalLeft || 'auto';
            panel.style.right = panel.dataset.originalRight || '20px';
            panel.style.bottom = panel.dataset.originalBottom || 'auto';
            panel.style.transform = panel.dataset.originalTransform || 'none';
            
            // Update button icon
            const resizeBtn = document.getElementById('panel-resize-btn');
            if (resizeBtn) {
                resizeBtn.innerHTML = '<i class="fas fa-expand-arrows-alt"></i>';
                resizeBtn.title = 'Maximize panel';
            }
        } else {
            // Save current dimensions and position
            panel.dataset.originalWidth = panel.style.width || '420px';
            panel.dataset.originalHeight = panel.style.height || 'auto';
            panel.dataset.originalMaxHeight = panel.style.maxHeight || '600px';
            panel.dataset.originalTop = panel.style.top || '80px';
            panel.dataset.originalLeft = panel.style.left || 'auto';
            panel.dataset.originalRight = panel.style.right || '20px';
            panel.dataset.originalBottom = panel.style.bottom || 'auto';
            panel.dataset.originalTransform = panel.style.transform || 'none';
            
            // Maximize
            panel.classList.add('maximized');
            panel.style.width = 'calc(100vw - 40px)';
            panel.style.height = 'calc(100vh - 160px)';
            panel.style.maxHeight = 'calc(100vh - 160px)';
            panel.style.top = '80px';
            panel.style.left = '20px';
            panel.style.right = '20px';
            panel.style.bottom = '20px';
            panel.style.transform = 'none';
            
            // Update button icon
            const resizeBtn = document.getElementById('panel-resize-btn');
            if (resizeBtn) {
                resizeBtn.innerHTML = '<i class="fas fa-compress-arrows-alt"></i>';
                resizeBtn.title = 'Restore panel size';
            }
        }
    }

    async analyzeQueryResults(queryType, queryString, graphData) {
        if (!this.isEnabled) {
            console.log('AI analysis is disabled');
            return;
        }
        
        if (!this.analysisPanel) {
            console.warn('Analysis panel not ready, skipping analysis');
            return;
        }
        
        if (this.isAnalyzing) return;
        
        this.isAnalyzing = true;
        this.showPanel();
        this.showLoading();

        try {
            const analysisData = this.extractAnalysisData(graphData, queryType);
            const graphStats = this.calculateGraphStats(graphData);
            
            const response = await fetch('/api/analyze-security-pattern', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCsrfToken(),
                },
                body: JSON.stringify({
                    query_type: queryType,
                    query_string: queryString,
                    analysis_data: analysisData,
                    graph_stats: graphStats
                })
            });

            const result = await response.json();
            
            if (result.success) {
                this.currentAnalysis = result.analysis;
                this.displayAnalysis(result.analysis);
            } else {
                this.displayError(result.error || 'Analysis failed');
            }
        } catch (error) {
            console.error('AI analysis error:', error);
            this.displayError('Failed to analyze security patterns: ' + error.message);
        } finally {
            this.isAnalyzing = false;
        }
    }

    extractAnalysisData(graphData, queryType) {
        const nodes = graphData.nodes || [];
        const edges = graphData.edges || [];
        
        // ユーザー情報の詳細抽出
        const users = nodes.filter(n => n.data.label === 'Username')
                          .map(n => ({
                              name: n.data.nlabel || n.data.id,
                              privilege: n.data.nprivilege || 'Unknown',
                              status: n.data.nstatus || 'Unknown',
                              rights: n.data.nrights || 'Unknown',
                              rank: n.data.nrank || null,
                              node_id: n.data.id
                          }));
        
        // ホスト情報の詳細抽出
        const hosts = nodes.filter(n => n.data.label === 'IPAddress')
                          .map(n => ({
                              ip: n.data.nlabel || n.data.id,
                              hostname: n.data.nhostname || 'Unknown',
                              rank: n.data.nrank || null,
                              node_id: n.data.id
                          }));
        
        // イベント情報の詳細抽出
        const events = edges.filter(e => e.data.label === 'Event')
                           .map(e => ({
                               event_id: e.data.eid || 'Unknown',
                               logon_type: e.data.logintype || e.data.logontype || 'Unknown',
                               auth_method: e.data.authname || 'Unknown',
                               count: parseInt(e.data.count) || 1,
                               status: e.data.status || 'Unknown',
                               source_user: this.getNodeLabel(e.data.source, nodes),
                               target_host: this.getNodeLabel(e.data.target, nodes),
                               source_id: e.data.source,
                               target_id: e.data.target,
                               date: e.data.date || 'Unknown'
                           }));

        // ネットワーク関係性の分析
        const userHostRelations = this.analyzeUserHostRelations(events, users, hosts);
        
        return {
            query_type: queryType,
            users: users,
            hosts: hosts,
            events: events,
            network_relations: userHostRelations,
            
            // 統計情報
            total_users: users.length,
            total_hosts: hosts.length,
            total_events: events.length,
            system_users: users.filter(u => u.privilege === 'SYSTEM' || u.rights === 'system').length,
            failed_logons: events.filter(e => e.event_id === '4625').length,
            ntlm_events: events.filter(e => e.auth_method === 'NTLM').length,
            rdp_events: events.filter(e => e.logon_type === '10').length,
            
            // グラフ構造分析
            user_host_diversity: this.calculateUserHostDiversity(events),
            host_user_diversity: this.calculateHostUserDiversity(events),
            authentication_patterns: this.analyzeAuthenticationPatterns(events)
        };
    }

    getNodeLabel(nodeId, nodes) {
        const node = nodes.find(n => n.data.id === nodeId);
        return node ? (node.data.nlabel || node.data.id) : 'Unknown';
    }

    analyzeUserHostRelations(events, users, hosts) {
        const relationshipDetails = [];
        const userHostConnections = {};
        
        // イベントから具体的なリレーションシップを構築
        events.forEach(event => {
            const user = event.source_user;
            const host = event.target_host;
            const eventId = event.event_id;
            const logonType = event.logon_type;
            const authMethod = event.auth_method;
            const count = event.count || 1;
            
            if (user && host && eventId) {
                const connectionKey = `${user}-${host}`;
                
                if (!userHostConnections[connectionKey]) {
                    userHostConnections[connectionKey] = {
                        user: user,
                        host: host,
                        events: {},
                        total_events: 0
                    };
                }
                
                // イベント情報を集約
                const eventKey = this.formatEventDescription(eventId, logonType, authMethod);
                if (!userHostConnections[connectionKey].events[eventKey]) {
                    userHostConnections[connectionKey].events[eventKey] = 0;
                }
                userHostConnections[connectionKey].events[eventKey] += count;
                userHostConnections[connectionKey].total_events += count;
            }
        });
        
        // フォーマットされたリレーションシップ文字列を生成
        Object.values(userHostConnections).forEach(connection => {
            const eventDescriptions = Object.entries(connection.events)
                .map(([eventDesc, count]) => count > 1 ? `${eventDesc}(×${count})` : eventDesc)
                .join(', ');
            
            relationshipDetails.push({
                user: connection.user,
                host: connection.host,
                events: eventDescriptions,
                total_events: connection.total_events,
                formatted: `${connection.user} - ${eventDescriptions} - ${connection.host}`
            });
        });
        
        // イベント数でソート（多い順）
        relationshipDetails.sort((a, b) => b.total_events - a.total_events);
        
        return {
            detailed_connections: relationshipDetails,
            summary: {
                total_connections: relationshipDetails.length,
                unique_users: new Set(relationshipDetails.map(r => r.user)).size,
                unique_hosts: new Set(relationshipDetails.map(r => r.host)).size
            }
        };
    }

    formatEventDescription(eventId, logonType, authMethod) {
        let description = eventId || 'Unknown';
        
        // ログオンタイプの追加
        if (logonType) {
            const logonTypeDesc = this.getLogonTypeDescription(logonType);
            if (logonTypeDesc) {
                description += `(${logonTypeDesc})`;
            } else {
                description += `(Type ${logonType})`;
            }
        }
        
        // 認証方式の追加
        if (authMethod && authMethod !== 'Unknown' && authMethod !== 'unknown') {
            description += `, ${authMethod}`;
        }
        
        return description;
    }

    getLogonTypeDescription(logonType) {
        const logonTypes = {
            '2': 'Interactive',
            '3': 'Network',
            '4': 'Batch',
            '5': 'Service',
            '7': 'Unlock',
            '8': 'NetworkCleartext',
            '9': 'NewCredentials',
            '10': 'RemoteInteractive',
            '11': 'CachedInteractive'
        };
        return logonTypes[String(logonType)] || null;
    }

    calculateUserHostDiversity(events) {
        const userHosts = {};
        events.forEach(event => {
            const user = event.source_user;
            const host = event.target_host;
            if (user && host) {
                if (!userHosts[user]) userHosts[user] = new Set();
                userHosts[user].add(host);
            }
        });
        
        const diversityScores = Object.entries(userHosts).map(([user, hostSet]) => ({
            user: user,
            unique_hosts: hostSet.size
        }));
        
        return diversityScores.sort((a, b) => b.unique_hosts - a.unique_hosts).slice(0, 10);
    }

    calculateHostUserDiversity(events) {
        const hostUsers = {};
        events.forEach(event => {
            const user = event.source_user;
            const host = event.target_host;
            if (user && host) {
                if (!hostUsers[host]) hostUsers[host] = new Set();
                hostUsers[host].add(user);
            }
        });
        
        const diversityScores = Object.entries(hostUsers).map(([host, userSet]) => ({
            host: host,
            unique_users: userSet.size
        }));
        
        return diversityScores.sort((a, b) => b.unique_users - a.unique_users).slice(0, 10);
    }

    analyzeAuthenticationPatterns(events) {
        const patterns = {
            logon_type_distribution: {},
            auth_method_distribution: {},
            event_id_distribution: {},
            time_patterns: {}
        };
        
        events.forEach(event => {
            // ログオンタイプ分布
            const logonType = event.logon_type;
            patterns.logon_type_distribution[logonType] = (patterns.logon_type_distribution[logonType] || 0) + 1;
            
            // 認証方法分布
            const authMethod = event.auth_method;
            patterns.auth_method_distribution[authMethod] = (patterns.auth_method_distribution[authMethod] || 0) + 1;
            
            // イベントID分布
            const eventId = event.event_id;
            patterns.event_id_distribution[eventId] = (patterns.event_id_distribution[eventId] || 0) + 1;
        });
        
        return patterns;
    }

    isInternalFreeformFallbackText(value) {
        const text = String(value || '');
        return text.includes('Analysis provided in free-form text') ||
            text.includes('Review the full analysis for security concerns') ||
            text.includes('Refer to the detailed analysis for recommendations') ||
            text.includes('Unable to connect to the local Ollama service') ||
            text.includes('Local LLM service is unreachable') ||
            text.includes('Automated threat detection is temporarily offline') ||
            text.includes('Verify the Ollama container is running') ||
            text.includes('Check the configured Ollama base URL') ||
            text.includes('Pull the selected model before running analysis') ||
            text.includes('Review LogonTracer and Ollama container logs');
    }

    filterInternalFreeformFallbackItems(items) {
        return Array.isArray(items)
            ? items.filter(item => !this.isInternalFreeformFallbackText(item))
            : [];
    }

    sanitizeAnalysisForDisplay(analysis) {
        if (!analysis || typeof analysis !== 'object' || Array.isArray(analysis)) {
            return analysis;
        }

        return {
            ...analysis,
            key_findings: this.filterInternalFreeformFallbackItems(analysis.key_findings),
            security_concerns: this.filterInternalFreeformFallbackItems(analysis.security_concerns),
            recommendations: this.filterInternalFreeformFallbackItems(analysis.recommendations)
        };
    }

    isInternalFreeformFallbackStep(step) {
        const analysis = step?.analysis || {};
        const internalDiagnostic = [
            step?.error,
            analysis.error_message,
            analysis.summary,
            ...(Array.isArray(analysis.key_findings) ? analysis.key_findings : []),
            ...(Array.isArray(analysis.security_concerns) ? analysis.security_concerns : []),
            ...(Array.isArray(analysis.recommendations) ? analysis.recommendations : [])
        ].some(value => this.isInternalFreeformFallbackText(value));

        return internalDiagnostic &&
            (step?.focus === 'Query Generation' ||
             this.isInternalFreeformFallbackText(analysis.summary) ||
             this.isInternalFreeformFallbackText(analysis.error_message));
    }

    getVisibleErrorText(value, fallback = '') {
        return this.isInternalFreeformFallbackText(value) ? fallback : String(value || fallback);
    }

    displayAnalysis(analysis) {
        const content = document.getElementById('analysis-content');
        
        // JSONデータの検証と解析
        let parsedAnalysis = analysis;
        
        // もしanalysisが文字列の場合、JSONとしてパースを試みる
        if (typeof analysis === 'string') {
            try {
                parsedAnalysis = JSON.parse(analysis);
            } catch (e) {
                // JSONパースに失敗した場合、rawテキストとして表示
                this.displayRawAnalysis(analysis);
                return;
            }
        }
        
        // JSONが不完全な場合やsummaryのみの場合の処理
        if (typeof parsedAnalysis.summary === 'string' && 
            parsedAnalysis.summary.startsWith('{') && 
            !parsedAnalysis.risk_level) {
            try {
                // summaryフィールド内にJSONが含まれている場合
                const nestedJson = JSON.parse(parsedAnalysis.summary);
                parsedAnalysis = nestedJson;
            } catch (e) {
                // パースに失敗した場合、rawテキストとして表示
                this.displayRawAnalysis(parsedAnalysis.summary);
                return;
            }
        }
        
        // Check if this is a quota exceeded error
        const isQuotaError = parsedAnalysis.summary && parsedAnalysis.summary.includes('quota exceeded');
        const isAuthError = parsedAnalysis.summary && parsedAnalysis.summary.includes('authentication failed');
        const isConnectionError = parsedAnalysis.summary && (
            parsedAnalysis.summary.includes('connect to OpenAI') ||
            parsedAnalysis.summary.includes('connect to the local Ollama service')
        );
        const isInternalLocalLlmError = parsedAnalysis.summary &&
            parsedAnalysis.summary.includes('connect to the local Ollama service');
        const isTimeoutError = parsedAnalysis.summary && parsedAnalysis.summary.includes('timed out');
        
        if (isQuotaError) {
            this.displayQuotaError(parsedAnalysis);
            return;
        }
        
        if (isInternalLocalLlmError) {
            this.displayError('AI analysis could not be completed. Review the LogonTracer server logs for details.');
            return;
        }

        if (isAuthError || isConnectionError || isTimeoutError) {
            this.displayServiceError(parsedAnalysis);
            return;
        }
        
        this.displayFormattedAnalysis(this.sanitizeAnalysisForDisplay(parsedAnalysis));
        this.updateHistoryButtonVisibility();
    }

    displayRawAnalysis(rawText) {
        const content = document.getElementById('analysis-content');
        const collapsibleId = 'raw-analysis-' + Date.now();
        const isLongText = rawText.length > 500;
        const displayText = isLongText ? rawText.substring(0, 500) + '...' : rawText;
        const safeDisplayText = this.escapeHtml(displayText);
        const safeFullText = this.escapeHtml(this.formatJSON(rawText));
        
        content.innerHTML = `
            <div class="analysis-result">
                <div class="analysis-summary" style="margin-bottom: 20px;">
                    <h6 style="margin-bottom: 10px; color: #333; font-weight: 600; display: flex; align-items: center;">
                        <i class="fas fa-file-alt" style="margin-right: 8px; color: #667eea;"></i>
                        Analysis Summary
                        ${isLongText ? `<button onclick="toggleContent('${collapsibleId}')" style="margin-left: auto; background: none; border: 1px solid #ccc; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 12px;">
                            <i class="fas fa-expand-alt"></i> Show Full
                        </button>` : ''}
                    </h6>
                    <div class="summary-content" style="background: #f8f9fa; padding: 12px; border-radius: 4px; border-left: 4px solid #667eea;">
                        <div id="${collapsibleId}-preview" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px; font-family: monospace; white-space: pre-wrap; ${isLongText ? '' : 'display: none;'}">${safeDisplayText}</div>
                        <div id="${collapsibleId}-full" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px; font-family: monospace; white-space: pre-wrap; max-height: 400px; overflow-y: auto; ${isLongText ? 'display: none;' : ''}">${safeFullText}</div>
                    </div>
                </div>
            </div>
        `;
        this.updateHistoryButtonVisibility();
    }

    displayFormattedAnalysis(analysis) {
        const content = document.getElementById('analysis-content');
        const riskColor = this.getRiskColor(analysis.risk_level);
        const riskIcon = this.getRiskIcon(analysis.risk_level);
        const summaryCollapsibleId = 'summary-' + Date.now();
        const isLongSummary = analysis.summary && analysis.summary.length > 300;
        const safeRiskLevel = this.escapeHtml(analysis.risk_level || 'Unknown');
        const safeSummary = this.escapeHtml(analysis.summary || '');
        const safeSummaryPreview = this.escapeHtml((analysis.summary || '').substring(0, 300));
        const safeFindings = Array.isArray(analysis.key_findings) ? analysis.key_findings.map(finding => this.escapeHtml(finding)) : [];
        const safeConcerns = Array.isArray(analysis.security_concerns) ? analysis.security_concerns.map(concern => this.escapeHtml(concern)) : [];
        const safeRecommendations = Array.isArray(analysis.recommendations) ? analysis.recommendations.map(rec => this.escapeHtml(rec)) : [];
        const metadata = analysis.analysis_metadata || {};
        
        content.innerHTML = `
            <div class="analysis-result">
                <div class="risk-assessment" style="margin-bottom: 20px;">
                    <div class="risk-badge" style="background: ${riskColor}; color: white; padding: 10px 15px; border-radius: 6px; display: flex; align-items: center; font-weight: 600;">
                        <i class="${riskIcon}" style="margin-right: 8px;"></i>
                        ${safeRiskLevel} Risk Level
                    </div>
                </div>
                
                <div class="analysis-summary" style="margin-bottom: 20px;">
                    <h6 style="margin-bottom: 10px; color: #333; font-weight: 600; display: flex; align-items: center;">
                        <i class="fas fa-file-alt" style="margin-right: 8px; color: #667eea;"></i>
                        Analysis Summary
                        ${isLongSummary ? `<button onclick="toggleContent('${summaryCollapsibleId}')" style="margin-left: auto; background: none; border: 1px solid #ccc; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 12px;">
                            <i class="fas fa-expand-alt"></i> <span id="${summaryCollapsibleId}-toggle-text">Expand</span>
                        </button>` : ''}
                    </h6>
                    <div style="background: #f8f9fa; padding: 12px; border-radius: 4px; border-left: 4px solid #667eea;">
                        ${isLongSummary ? `
                            <div id="${summaryCollapsibleId}-preview" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px;">${safeSummaryPreview}...</div>
                            <div id="${summaryCollapsibleId}-full" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px; display: none;">${safeSummary}</div>
                        ` : `<p style="margin: 0; line-height: 1.6; color: #555; font-size: 14px;">${safeSummary}</p>`}
                    </div>
                </div>

                ${safeFindings.length > 0 ? `
                <div class="key-findings" style="margin-bottom: 20px;">
                    <h6 style="margin-bottom: 10px; color: #333; font-weight: 600; display: flex; align-items: center;">
                        <i class="fas fa-search" style="margin-right: 8px; color: #28a745;"></i>
                        Key Findings
                    </h6>
                    <ul style="margin: 0; padding-left: 0; list-style: none;">
                        ${safeFindings.map(finding =>
                            `<li style="margin-bottom: 8px; padding: 8px 12px; background: #e8f5e8; border-radius: 4px; font-size: 14px; border-left: 3px solid #28a745;">
                                <i class="fas fa-check-circle" style="margin-right: 8px; color: #28a745;"></i>${finding}
                            </li>`
                        ).join('')}
                    </ul>
                </div>
                ` : ''}

                ${safeConcerns.length > 0 ? `
                <div class="security-concerns" style="margin-bottom: 20px;">
                    <h6 style="margin-bottom: 10px; color: #dc3545; font-weight: 600; display: flex; align-items: center;">
                        <i class="fas fa-exclamation-triangle" style="margin-right: 8px; color: #dc3545;"></i>
                        Security Concerns
                    </h6>
                    <ul style="margin: 0; padding-left: 0; list-style: none;">
                        ${safeConcerns.map(concern =>
                            `<li style="margin-bottom: 8px; padding: 8px 12px; background: #ffeaea; border-radius: 4px; font-size: 14px; border-left: 3px solid #dc3545;">
                                <i class="fas fa-times-circle" style="margin-right: 8px; color: #dc3545;"></i>${concern}
                            </li>`
                        ).join('')}
                    </ul>
                </div>
                ` : ''}

                <div class="recommendations" style="margin-bottom: 20px;">
                    <h6 style="margin-bottom: 10px; color: #17a2b8; font-weight: 600; display: flex; align-items: center;">
                        <i class="fas fa-lightbulb" style="margin-right: 8px; color: #17a2b8;"></i>
                        Recommendations
                    </h6>
                    <ul style="margin: 0; padding-left: 0; list-style: none;">
                        ${safeRecommendations.map(rec =>
                            `<li style="margin-bottom: 8px; padding: 8px 12px; background: #e6f3ff; border-radius: 4px; font-size: 14px; border-left: 3px solid #17a2b8;">
                                <i class="fas fa-arrow-right" style="margin-right: 8px; color: #17a2b8;"></i>${rec}
                            </li>`
                        ).join('')}
                    </ul>
                </div>

	                ${analysis.analysis_metadata ? `
                <div class="analysis-metadata" style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #eee;">
                    <small style="color: #6c757d; font-size: 11px;">
                        Analysis by ${this.escapeHtml(metadata.model || '')} • Query: ${this.escapeHtml(metadata.query_type || '')}
                    </small>
                </div>
                ` : ''}
            </div>
        `;
    }

    formatJSON(text) {
        try {
            // JSONかどうかチェック
            if (text.trim().startsWith('{') || text.trim().startsWith('[')) {
                const parsed = JSON.parse(text);
                return JSON.stringify(parsed, null, 2);
            }
            return text;
        } catch (e) {
            return text;
        }
    }

    getRiskColor(riskLevel) {
        const colors = {
            'Low': '#28a745',
            'Medium': '#ffc107', 
            'High': '#fd7e14',
            'Critical': '#dc3545',
            'Unknown': '#6c757d'
        };
        return colors[riskLevel] || colors.Unknown;
    }

    getRiskIcon(riskLevel) {
        const icons = {
            'Low': 'fas fa-check-circle',
            'Medium': 'fas fa-exclamation-circle',
            'High': 'fas fa-exclamation-triangle',
            'Critical': 'fas fa-times-circle',
            'Unknown': 'fas fa-question-circle'
        };
        return icons[riskLevel] || icons.Unknown;
    }

    showPanel() {
        if (!this.analysisPanel) {
            console.warn('Analysis panel not ready');
            return;
        }
        
        this.analysisPanel.style.display = 'block';
        // Add slide-in animation
        this.analysisPanel.style.transform = 'translateX(100%)';
        this.analysisPanel.style.transition = 'transform 0.3s ease-out';
        setTimeout(() => {
            if (this.analysisPanel) {
                this.analysisPanel.style.transform = 'translateX(0)';
            }
        }, 10);
    }

    hidePanel() {
        if (!this.analysisPanel) {
            console.warn('Analysis panel not ready');
            return;
        }
        
        this.analysisPanel.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (this.analysisPanel) {
                this.analysisPanel.style.display = 'none';
            }
        }, 300);
    }

    showLastAnalysis() {
        if (!this.currentAnalysis) {
            this.displayNoHistoryMessage();
            return;
        }
        
        this.showPanel();
        if (this.currentAnalysis.investigation_history || this.currentAnalysis.final_report) {
            this.displayAgentResults(this.currentAnalysis);
            return;
        }
        this.displayAnalysis(this.currentAnalysis);
        this.updateHistoryButtonVisibility();
    }

    displayNoHistoryMessage() {
        this.showPanel();
        const content = document.getElementById('analysis-content');
        content.innerHTML = `
            <div style="text-align: center; padding: 40px 20px;">
                <i class="fas fa-history" style="font-size: 48px; color: #ddd; margin-bottom: 15px;"></i>
                <h6 style="color: #666; margin-bottom: 10px;">No Previous Analysis</h6>
                <p style="color: #999; font-size: 14px; margin: 0;">
                    Run a query and use AI analysis to see results here.
                </p>
            </div>
        `;
        this.updateHistoryButtonVisibility();
    }

    updateHistoryButtonVisibility() {
        const historyBtn = document.getElementById('show-history-btn');
        if (historyBtn) {
            historyBtn.style.display = this.currentAnalysis ? 'inline-block' : 'none';
        }
        
        // Also update main interface button
        const mainHistoryBtn = document.getElementById('ai-history-btn');
        if (mainHistoryBtn) {
            if (this.currentAnalysis) {
                mainHistoryBtn.style.display = 'inline-block';
                mainHistoryBtn.disabled = false;
            } else {
                mainHistoryBtn.style.opacity = '0.5';
                mainHistoryBtn.disabled = true;
            }
        }
    }

    showLoading() {
        const content = document.getElementById('analysis-content');
        content.innerHTML = `
            <div class="loading-indicator" style="text-align: center; padding: 40px 20px;">
                <div class="spinner" style="border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 15px;"></div>
                <p style="margin: 0; color: #667eea; font-size: 16px; font-weight: 500;">Analyzing Security Patterns</p>
                <p style="margin: 5px 0 0 0; color: #999; font-size: 13px;">This may take a few moments...</p>
            </div>
            <style>
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            </style>
        `;
    }

    displayError(message) {
        if (this.analysisPanel && this.analysisPanel.style.display === 'none') {
            this.showPanel();
        }
        const content = document.getElementById('analysis-content');
        content.innerHTML = `
            <div class="error-message" style="text-align: center; padding: 30px 20px;">
                <i class="fas fa-exclamation-triangle" style="font-size: 32px; color: #dc3545; margin-bottom: 15px;"></i>
                <h6 style="color: #dc3545; margin-bottom: 10px;">Analysis Failed</h6>
                <p style="margin: 0; color: #6c757d; font-size: 14px; line-height: 1.5;">${this.escapeHtml(message)}</p>
                <button onclick="hideAIPanel()" style="margin-top: 15px; padding: 8px 16px; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px;">
                    Close
                </button>
            </div>
        `;
    }

    displayQuotaError(analysis) {
        const content = document.getElementById('analysis-content');
        content.innerHTML = `
            <div class="quota-error-message" style="text-align: center; padding: 20px;">
                <i class="fas fa-credit-card" style="font-size: 48px; color: #ff6b6b; margin-bottom: 20px;"></i>
                <h5 style="color: #ff6b6b; margin-bottom: 15px;">LLM API Quota Exceeded</h5>
                <p style="color: #666; margin-bottom: 20px; font-size: 14px; line-height: 1.5;">
                    Your configured LLM API usage has exceeded the current plan limits. 
                    AI-powered analysis is temporarily unavailable.
                </p>
                
                <div class="error-details" style="background: #fff5f5; border: 1px solid #fed7d7; border-radius: 6px; padding: 15px; margin: 20px 0; text-align: left;">
                    <h6 style="color: #c53030; margin-bottom: 10px; display: flex; align-items: center;">
                        <i class="fas fa-info-circle" style="margin-right: 8px;"></i>
                        What you can do:
                    </h6>
                    <ul style="margin: 0; padding-left: 20px; color: #666; font-size: 13px;">
	                        ${(Array.isArray(analysis.recommendations) ? analysis.recommendations : []).map(rec => `<li style="margin-bottom: 5px;">${this.escapeHtml(rec)}</li>`).join('')}
                    </ul>
                </div>
                
                <div style="margin-top: 20px;">
                    <button onclick="window.open('https://platform.openai.com/usage', '_blank')" 
                            style="margin-right: 10px; padding: 10px 16px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px;">
                        Check Usage
                    </button>
                    <button onclick="hideAIPanel()" 
                            style="padding: 10px 16px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px;">
                        Close
                    </button>
                </div>
            </div>
        `;
    }

    displayServiceError(analysis) {
        const content = document.getElementById('analysis-content');
        
        let errorIcon = 'fas fa-exclamation-triangle';
        let errorColor = '#ffc107';
        let errorTitle = 'Service Error';
        
        if (analysis.summary.includes('authentication')) {
            errorIcon = 'fas fa-key';
            errorColor = '#dc3545';
            errorTitle = 'Authentication Error';
        } else if (analysis.summary.includes('connect')) {
            errorIcon = 'fas fa-wifi';
            errorColor = '#17a2b8';
            errorTitle = 'Connection Error';
        } else if (analysis.summary.includes('timed out')) {
            errorIcon = 'fas fa-clock';
            errorColor = '#fd7e14';
            errorTitle = 'Timeout Error';
        }
        
        content.innerHTML = `
            <div class="service-error-message" style="text-align: center; padding: 20px;">
                <i class="${errorIcon}" style="font-size: 32px; color: ${errorColor}; margin-bottom: 15px;"></i>
                <h6 style="color: ${errorColor}; margin-bottom: 10px;">${errorTitle}</h6>
                <p style="margin: 0; color: #6c757d; font-size: 14px; line-height: 1.5; margin-bottom: 20px;">${this.escapeHtml(analysis.summary || '')}</p>
                
                <div class="error-recommendations" style="background: #f8f9fa; border-radius: 6px; padding: 15px; margin: 15px 0; text-align: left;">
                    <h6 style="color: #495057; margin-bottom: 10px;">Recommended Actions:</h6>
                    <ul style="margin: 0; padding-left: 20px; color: #666; font-size: 13px;">
                        ${(Array.isArray(analysis.recommendations) ? analysis.recommendations : []).map(rec => `<li style="margin-bottom: 5px;">${this.escapeHtml(rec)}</li>`).join('')}
                    </ul>
                </div>
                
                <button onclick="hideAIPanel()" style="margin-top: 15px; padding: 8px 16px; background: ${errorColor}; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px;">
                    Close
                </button>
            </div>
        `;
    }

    calculateGraphStats(graphData) {
        const nodes = graphData.nodes || [];
        const edges = graphData.edges || [];
        
        // 基本統計
        const nodesByType = {};
        const edgesByType = {};
        
        nodes.forEach(node => {
            const label = node.data.label || 'Unknown';
            nodesByType[label] = (nodesByType[label] || 0) + 1;
        });
        
        edges.forEach(edge => {
            const label = edge.data.label || 'Unknown';
            edgesByType[label] = (edgesByType[label] || 0) + 1;
        });
        
        // ネットワーク密度の計算
        const totalPossibleEdges = nodes.length * (nodes.length - 1) / 2;
        const density = totalPossibleEdges > 0 ? edges.length / totalPossibleEdges : 0;
        
        // 中心性分析
        const nodeDegrees = {};
        edges.forEach(edge => {
            const source = edge.data.source;
            const target = edge.data.target;
            
            nodeDegrees[source] = (nodeDegrees[source] || 0) + 1;
            nodeDegrees[target] = (nodeDegrees[target] || 0) + 1;
        });
        
        const degrees = Object.values(nodeDegrees);
        const maxDegree = Math.max(...degrees, 0);
        const avgDegree = degrees.length > 0 ? degrees.reduce((a, b) => a + b, 0) / degrees.length : 0;
        
        // 高度に接続されたノードの特定
        const highDegreeNodes = nodes.filter(node => {
            const degree = nodeDegrees[node.data.id] || 0;
            return degree > avgDegree * 1.5;
        }).map(node => ({
            id: node.data.id,
            label: node.data.nlabel || node.data.id,
            type: node.data.label,
            degree: nodeDegrees[node.data.id] || 0
        }));
        
        // コンポーネント分析
        const components = this.calculateConnectedComponents(nodes, edges);
        
        // セキュリティ関連統計
        const privilegedUsers = nodes.filter(n => 
            n.data.label === 'Username' && 
            (n.data.nprivilege === 'SYSTEM' || n.data.nrights === 'system')
        ).length;
        
        const suspiciousEvents = edges.filter(e => 
            e.data.label === 'Event' && 
            (e.data.eid === '4625' || e.data.logintype === '10' || e.data.authname === 'NTLM')
        ).length;
        
        return {
            basic_stats: {
                total_nodes: nodes.length,
                total_edges: edges.length,
                nodes_by_type: nodesByType,
                edges_by_type: edgesByType
            },
            network_topology: {
                density: density,
                max_degree: maxDegree,
                avg_degree: avgDegree,
                connected_components: components.length,
                largest_component_size: Math.max(...components.map(c => c.length), 0)
            },
            centrality_analysis: {
                high_degree_nodes: highDegreeNodes,
                degree_distribution: this.calculateDegreeDistribution(degrees)
            },
            security_metrics: {
                privileged_users: privilegedUsers,
                suspicious_events: suspiciousEvents,
                authentication_diversity: this.calculateAuthDiversity(edges)
            }
        };
    }

    calculateConnectedComponents(nodes, edges) {
        const visited = new Set();
        const components = [];
        const adjacencyList = {};
        
        // 隣接リストを作成
        nodes.forEach(node => {
            adjacencyList[node.data.id] = [];
        });
        
        edges.forEach(edge => {
            const source = edge.data.source;
            const target = edge.data.target;
            if (adjacencyList[source] && adjacencyList[target]) {
                adjacencyList[source].push(target);
                adjacencyList[target].push(source);
            }
        });
        
        // DFSで連結成分を発見
        const dfs = (nodeId, component) => {
            visited.add(nodeId);
            component.push(nodeId);
            
            (adjacencyList[nodeId] || []).forEach(neighbor => {
                if (!visited.has(neighbor)) {
                    dfs(neighbor, component);
                }
            });
        };
        
        nodes.forEach(node => {
            if (!visited.has(node.data.id)) {
                const component = [];
                dfs(node.data.id, component);
                components.push(component);
            }
        });
        
        return components;
    }

    calculateDegreeDistribution(degrees) {
        const distribution = {};
        degrees.forEach(degree => {
            distribution[degree] = (distribution[degree] || 0) + 1;
        });
        return distribution;
    }

    calculateAuthDiversity(edges) {
        const authMethods = new Set();
        const logonTypes = new Set();
        
        edges.filter(e => e.data.label === 'Event').forEach(edge => {
            if (edge.data.authname) {
                authMethods.add(edge.data.authname);
            }
            if (edge.data.logintype || edge.data.logontype) {
                logonTypes.add(edge.data.logintype || edge.data.logontype);
            }
        });
        
        return {
            auth_methods: Array.from(authMethods),
            logon_types: Array.from(logonTypes),
            auth_method_count: authMethods.size,
            logon_type_count: logonTypes.size
        };
    }

    // AI Agent Detection
    runAgentDetection(initialContext = "Detect suspicious logon behavior in Active Directory", options = {}) {
        if (!options.startImmediately) {
            this.showAgentStartOptions(initialContext);
            return;
        }

        return this.runAutonomousAgentDetection(initialContext);
    }

    showAgentStartOptions(initialContext = "Detect suspicious logon behavior in Active Directory") {
        if (!this.isEnabled) {
            this.displayError('AI Agent is disabled. Please enable it in settings.');
            return;
        }

        if (this.agentRunning) {
            this.displayError('AI Agent is already running. Please wait for the current investigation step to complete.');
            return;
        }

        this.showPanel();
        const content = document.getElementById('analysis-content');
        content.innerHTML = `
            <div class="agent-start-options">
                <h5 style="color: #667eea; margin-bottom: 14px;">
                    <i class="fas fa-robot" style="margin-right: 8px;"></i>AI Agent Investigation
                </h5>
                <div style="margin-bottom: 14px;">
                    <label for="agent-initial-context" style="display: block; font-weight: 600; color: #495057; margin-bottom: 6px;">Investigation context</label>
                    <textarea id="agent-initial-context" rows="4" style="width: 100%; border: 1px solid #ced4da; border-radius: 6px; padding: 10px; font-size: 13px; resize: vertical;">${this.escapeHtml(initialContext)}</textarea>
                </div>
                <label style="display: flex; align-items: flex-start; gap: 10px; padding: 12px; border: 1px solid #d8dee9; border-radius: 6px; background: #f8f9fa; margin-bottom: 16px; cursor: pointer;">
                    <input type="checkbox" id="agent-hitl-enabled" style="margin-top: 3px;">
                    <span>
                        <strong style="display: block; color: #333;">Enable Analyst-in-the-loop</strong>
                        <small style="color: #6c757d;">Review every investigation step, approve or override the next investigation step, and decide when to end.</small>
                    </span>
                </label>
                <div style="display: flex; gap: 10px; justify-content: flex-end; flex-wrap: wrap;">
                    <button class="btn btn-outline-secondary" onclick="hideAIPanel()">Cancel</button>
                    <button class="btn btn-primary" onclick="aiAssistant.startAgentDetectionFromOptions()" style="background: #667eea; border-color: #667eea;">
                        <i class="fas fa-play" style="margin-right: 6px;"></i>Start
                    </button>
                </div>
            </div>
        `;
    }

    startAgentDetectionFromOptions() {
        const contextInput = document.getElementById('agent-initial-context');
        const hitlInput = document.getElementById('agent-hitl-enabled');
        const initialContext = (contextInput?.value || 'Detect suspicious logon behavior in Active Directory').trim();
        const analystInLoop = Boolean(hitlInput?.checked);

        if (analystInLoop) {
            this.startHitlDetection(initialContext);
        } else {
            this.runAgentDetection(initialContext, { startImmediately: true });
        }
    }

    async runAutonomousAgentDetection(initialContext = "Detect suspicious logon behavior in Active Directory") {
        // Run autonomous threat detection using AI Agent
        if (!this.isEnabled) {
            this.displayError('AI Agent is disabled. Please enable it in settings.');
            return;
        }

        if (this.agentRunning) {
            this.displayError('AI Agent is already running. Please wait for current investigation to complete.');
            return;
        }

        this.agentRunning = true;

        try {
            this.showPanel();
            this.showAgentLoading();
            
            const response = await fetch('/api/ai/agent-detect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCsrfToken(),
                },
                body: JSON.stringify({
                    context: initialContext,
                    analyst_in_loop: false
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const result = await response.json();
            
            if (result.success === false) {
                this.displayError(`Agent Detection Error: ${result.error}`);
                return;
            }

            if (!result.job_id) {
                throw new Error('Agent progress job id was not returned.');
            }

            this.currentAgentJobId = result.job_id;
            await this.pollAutonomousAgentProgress(result.job_id);
            
        } catch (error) {
            console.error('Error running AI agent detection:', error);
            this.displayError(`Failed to run AI agent detection: ${error.message}`);
        } finally {
            this.agentRunning = false;
            this.currentAgentJobId = null;
        }
    }

    async pollAutonomousAgentProgress(jobId) {
        while (this.agentRunning && this.currentAgentJobId === jobId) {
            const response = await fetch(`/api/ai/agent-detect/${encodeURIComponent(jobId)}`);
            if (!response.ok) {
                throw new Error(`Progress request failed with status ${response.status}`);
            }

            const result = await response.json();
            if (result.success === false || result.status === 'failed') {
                throw new Error(result.error || 'AI agent investigation failed.');
            }

            if (result.status === 'completed') {
                this.currentAnalysis = result;
                this.displayAgentResults(result);
                return;
            }

            this.displayAgentProgress(result);
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }

    async startHitlDetection(initialContext = "Detect suspicious logon behavior in Active Directory") {
        if (!this.isEnabled) {
            this.displayError('AI Agent is disabled. Please enable it in settings.');
            return;
        }

        if (this.agentRunning) {
            this.displayError('AI Agent is already running. Please wait for the current investigation step to complete.');
            return;
        }

        this.hitlSession = {
            id: null,
            context: initialContext,
            iteration: 0,
            investigation_history: [],
            discovered_threats: [],
            analyst_feedback: [],
            max_iterations: null,
            pending_step: null,
            proposed_next_context: initialContext
        };

        await this.runHitlStep();
    }

    async runHitlStep(nextContext = null, analystFeedback = null) {
        if (!this.hitlSession) return;

        if (this.hitlSession.max_iterations !== null && this.hitlSession.iteration >= this.hitlSession.max_iterations) {
            await this.finalizeHitlInvestigation('max_iterations_reached');
            return;
        }

        this.agentRunning = true;
        this.showPanel();
        this.showHitlLoading();

        try {
            const response = await fetch('/api/ai/agent-step', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCsrfToken(),
                },
                body: JSON.stringify({
                    hitl_session_id: this.hitlSession.id,
                    context: nextContext || this.hitlSession.context,
                    analyst_feedback: analystFeedback
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            this.hitlSession.id = result.hitl_session_id || this.hitlSession.id;
            if (result.success === false) {
                this.displayError(`Analyst-in-the-loop Error: ${result.error}`);
                return;
            }

            this.hitlSession.investigation_history = result.investigation_history || [];
            this.hitlSession.discovered_threats = result.discovered_threats || [];
            this.hitlSession.iteration = result.next_iteration ?? this.hitlSession.investigation_history.length;
            this.hitlSession.max_iterations = result.max_iterations ?? this.hitlSession.max_iterations;
            this.hitlSession.pending_step = result.step;
            this.hitlSession.proposed_next_context = result.next_investigation_context || this.hitlSession.context;

            this.displayHitlStepReview(result);
        } catch (error) {
            console.error('Error running HITL AI agent step:', error);
            this.displayError(`Failed to run analyst-in-the-loop step: ${error.message}`);
        } finally {
            this.agentRunning = false;
        }
    }

    showHitlLoading() {
        const content = document.getElementById('analysis-content');
        content.innerHTML = `
            <div class="agent-loading" style="text-align: center; padding: 40px 20px;">
                <div class="agent-spinner" style="border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 54px; height: 54px; animation: spin 1s linear infinite; margin: 0 auto 20px;"></div>
                <h5 style="color: #667eea; margin-bottom: 12px;">Analyst-in-the-loop Investigation</h5>
                <p style="margin: 0; color: #667eea; font-size: 15px; font-weight: 500;">Running one investigation step...</p>
                <p style="margin: 10px 0 0 0; color: #999; font-size: 13px;">The agent will pause for Analyst review after this step.</p>
            </div>
            <style>
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            </style>
        `;
    }

    extractCypherQuery(text) {
        if (!text) return '';
        const value = String(text).trim();
        const matchIndex = value.search(/\b(MATCH|WITH)\b/i);
        return matchIndex >= 0 ? value.substring(matchIndex).trim() : value;
    }

    describeCypherIntent(cypherQuery) {
        const query = String(cypherQuery || '').toLowerCase();
        if (!query) return '';

        if (query.includes('u.rights') && query.includes('system')) {
            return 'The next step will review privileged or system-rights accounts to identify possible privilege escalation or high-impact account misuse.';
        }
        if (query.includes('e.id=4769') || query.includes('e.id = 4769')) {
            return 'The next step will review Kerberos service ticket activity to look for Kerberoasting exposure or unusual service access patterns.';
        }
        if (query.includes('e.id=4768') || query.includes('e.id = 4768')) {
            return 'The next step will review Kerberos TGT activity to look for weak encryption or AS-REP roasting related indicators.';
        }
        if (query.includes('e.id=4776') || query.includes('e.id = 4776') || query.includes('microsoft_authentication_package_v1_0')) {
            return 'The next step will review NTLM authentication activity to look for credential reuse, pass-the-hash style movement, or suspicious spread.';
        }
        if (query.includes('logintype=10') || query.includes('logintype = 10')) {
            return 'The next step will review RDP logons to look for remote interactive movement across hosts.';
        }
        if (query.includes('logintype=3') || query.includes('logintype = 3')) {
            return 'The next step will review network logons to look for lateral movement or broad remote access patterns.';
        }
        if (query.includes('logintype in [9,8]') || query.includes('logintype in [8,9]')) {
            return 'The next step will review NewCredentials or NetworkCleartext logons to look for credential misuse.';
        }
        if (query.includes('i.hostname') && query.includes('dc')) {
            return 'The next step will review access to domain-controller-like hosts to identify unusual authentication to critical infrastructure.';
        }

        return '';
    }

    getNextStepDetails(result) {
        const step = result.step || {};
        const analysis = step.analysis || {};
        const rawContext = result.next_investigation_context || analysis.next_investigation_context || '';
        const explicitQuery = analysis.next_cypher_query || analysis.next_investigation_query || '';
        const cypherQuery = this.extractCypherQuery(explicitQuery || rawContext);
        const rawText = String(rawContext || '').trim();
        const matchIndex = rawText.search(/\b(MATCH|WITH)\b/i);
        const explanationFromContext = matchIndex > 0 ? rawText.substring(0, matchIndex).trim() : '';
        const explanation = analysis.next_investigation_explanation ||
            analysis.next_step_description ||
            analysis.next_investigation_rationale ||
            explanationFromContext ||
            this.describeCypherIntent(cypherQuery) ||
            'The agent will continue with the next distinct investigation target to improve coverage.';
        const executableContext = cypherQuery || rawContext || explanation;

        return {
            explanation,
            cypherQuery,
            context: executableContext
        };
    }

    displayHitlStepReview(result) {
        const content = document.getElementById('analysis-content');
        const step = result.step || {};
        const analysis = step.analysis || {};
        const queryGeneration = step.query_generation || {};
        const noResults = (Number(step.results_count || 0) === 0) && !step.error;
        if (noResults) {
            this.displayHitlNoResultStep(result);
            return;
        }

        const evidence = Array.isArray(analysis.evidence) ? analysis.evidence : [];
        const recommendations = this.filterInternalFreeformFallbackItems(analysis.recommendations);
        const nextStep = this.getNextStepDetails(result);
        const completeText = result.investigation_complete ? '<span style="color: #198754; font-weight: 600;">AI agent suggests completion</span>' : '<span style="color: #667eea; font-weight: 600;">AI agent suggests continuing</span>';
        const severity = analysis.severity || 'unknown';
        const threatDetected = analysis.threat_detected ? 'Threat detected' : 'No threat detected';
        const analysisDetails = this.getVisibleErrorText(
            analysis.threat_description || analysis.error_message,
            'No detailed analysis returned.'
        );

        content.innerHTML = `
            <div class="hitl-review">
                <div style="display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 14px;">
                    <h5 style="color: #667eea; margin: 0;">
                        <i class="fas fa-user-check" style="margin-right: 8px;"></i>Analyst Review: Step ${this.escapeHtml(step.iteration || result.iteration)}
                    </h5>
                    <span style="font-size: 12px; color: #6c757d;">${this.escapeHtml(this.hitlSession?.iteration || 0)} / ${this.escapeHtml(result.max_iterations || '?')}</span>
                </div>

                <div style="border-left: 4px solid #667eea; background: #f8f9fa; padding: 12px; border-radius: 0 6px 6px 0; margin-bottom: 14px;">
                    <div style="font-weight: 600; color: #333; margin-bottom: 6px;">${this.escapeHtml(step.focus || 'General analysis')}</div>
                    <div style="font-size: 13px; color: #555; margin-bottom: 8px;">${this.escapeHtml(queryGeneration.expected_findings || '')}</div>
                    <div style="font-size: 12px; color: #6c757d; margin-top: 8px;">Results: ${this.escapeHtml(step.results_count || 0)} ${step.error && !this.isInternalFreeformFallbackText(step.error) ? ` | Error: ${this.escapeHtml(step.error)}` : ''}</div>
                    <details style="margin-top: 8px;">
                        <summary style="cursor: pointer; color: #667eea; font-size: 12px;">Show executed Cypher query</summary>
                        <pre style="white-space: pre-wrap; word-break: break-word; background: #fff; border: 1px solid #dee2e6; border-radius: 4px; padding: 8px; font-size: 12px; margin: 8px 0 0 0;">${this.escapeHtml(step.query || '')}</pre>
                    </details>
                </div>

                <div style="margin-bottom: 14px;">
                    <h6 style="color: #495057; margin-bottom: 8px;"><i class="fas fa-search" style="margin-right: 6px;"></i>AI Agent Analysis</h6>
                    <div style="background: #fff; border: 1px solid #dee2e6; border-radius: 6px; padding: 12px;">
                        <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px;">
                            <span class="badge" style="background: ${analysis.threat_detected ? '#dc3545' : '#198754'};">${this.escapeHtml(threatDetected)}</span>
                            <span class="badge" style="background: ${this.getThreatSeverityColor(severity)};">${this.escapeHtml(severity)}</span>
                            <span style="font-size: 12px;">${completeText}</span>
                        </div>
                        <p style="font-size: 13px; color: #555; margin: 0 0 8px 0; line-height: 1.5;">${this.escapeHtml(analysisDetails)}</p>
                        ${evidence.length > 0 ? `
                            <div style="font-size: 13px; margin-top: 8px;">
                                <strong>Evidence</strong>
                                <ul style="margin: 6px 0 0 18px; padding: 0;">${evidence.map(item => `<li>${this.escapeHtml(item)}</li>`).join('')}</ul>
                            </div>
                        ` : ''}
                        ${recommendations.length > 0 ? `
                            <div style="font-size: 13px; margin-top: 8px;">
                                <strong>Recommendations</strong>
                                <ul style="margin: 6px 0 0 18px; padding: 0;">${recommendations.map(item => `<li>${this.escapeHtml(item)}</li>`).join('')}</ul>
                            </div>
                        ` : ''}
                    </div>
                </div>

                <div style="border: 1px solid #d8dee9; border-radius: 6px; padding: 12px; background: #f8f9fa; margin-bottom: 14px;">
                    <div style="font-weight: 600; color: #333; margin-bottom: 8px;">Analyst verdict</div>
                    <div style="display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 10px;">
                        <label><input type="radio" name="hitl-verdict" value="malicious"> malicious</label>
                        <label><input type="radio" name="hitl-verdict" value="benign"> benign</label>
                        <label><input type="radio" name="hitl-verdict" value="unknown" checked> unknown</label>
                    </div>
                    <textarea id="hitl-analyst-prompt" rows="3" placeholder="Prompt to AI agent: explain why, add context, or specify what evidence matters next." style="width: 100%; border: 1px solid #ced4da; border-radius: 6px; padding: 9px; font-size: 12px; resize: vertical;"></textarea>
                </div>

                <div style="border: 1px solid #d8dee9; border-radius: 6px; padding: 12px; background: #fff; margin-bottom: 14px;">
                    <h6 style="color: #495057; margin-bottom: 8px;"><i class="fas fa-route" style="margin-right: 6px;"></i>Proposed Next Step</h6>
                    <p style="font-size: 13px; color: #555; line-height: 1.5; margin: 0 0 10px 0;">${this.escapeHtml(nextStep.explanation)}</p>
                    <textarea id="hitl-next-context" style="display: none;">${this.escapeHtml(nextStep.context)}</textarea>
                    <details style="margin-bottom: 12px;">
                        <summary style="cursor: pointer; color: #667eea; font-size: 12px;">Show proposed Cypher query</summary>
                        <pre style="white-space: pre-wrap; word-break: break-word; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 8px; font-size: 12px; margin: 8px 0 0 0;">${this.escapeHtml(nextStep.cypherQuery || nextStep.context)}</pre>
                    </details>

                    <div style="display: grid; gap: 10px;">
                        <button class="btn btn-primary" onclick="aiAssistant.submitHitlDecision('accept')" style="background: #667eea; border-color: #667eea; text-align: left; padding: 12px;">
                            <strong><i class="fas fa-check" style="margin-right: 6px;"></i>Approve proposed next step</strong>
                            <span style="display: block; font-size: 12px; opacity: 0.9; margin-top: 3px;">Use the AI agent proposal and continue the investigation.</span>
                        </button>
                        <div style="border: 1px solid #dee2e6; border-radius: 6px; padding: 10px; background: #f8f9fa;">
                            <label for="hitl-custom-instruction" style="display: block; font-weight: 600; color: #495057; margin-bottom: 6px;">Reject proposed step and instruct AI agent</label>
                            <textarea id="hitl-custom-instruction" rows="3" placeholder="Describe what the AI agent should investigate instead." style="width: 100%; border: 1px solid #ced4da; border-radius: 6px; padding: 9px; font-size: 12px; resize: vertical; margin-bottom: 8px;"></textarea>
                            <button class="btn btn-outline-secondary" onclick="aiAssistant.submitHitlDecision('override')" style="width: 100%; text-align: left;">
                                <strong><i class="fas fa-pen" style="margin-right: 6px;"></i>Run my instruction instead</strong>
                            </button>
                        </div>
                        <button class="btn btn-outline-danger" onclick="aiAssistant.submitHitlDecision('end')" style="text-align: left; padding: 10px;">
                            <strong><i class="fas fa-stop" style="margin-right: 6px;"></i>End investigation</strong>
                            <span style="display: block; font-size: 12px; margin-top: 3px;">Stop now and generate the final report.</span>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    displayHitlNoResultStep(result) {
        const content = document.getElementById('analysis-content');
        const step = result.step || {};
        const queryGeneration = step.query_generation || {};
        const nextStep = this.getNextStepDetails(result);

        content.innerHTML = `
            <div class="hitl-review">
                <div style="display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 14px;">
                    <h5 style="color: #198754; margin: 0;">
                        <i class="fas fa-check-circle" style="margin-right: 8px;"></i>No Suspicious Activity: Step ${this.escapeHtml(step.iteration || result.iteration)}
                    </h5>
                    <span style="font-size: 12px; color: #6c757d;">${this.escapeHtml(this.hitlSession?.iteration || 0)} / ${this.escapeHtml(result.max_iterations || '?')}</span>
                </div>

                <div style="border-left: 4px solid #198754; background: #f0fff4; padding: 12px; border-radius: 0 6px 6px 0; margin-bottom: 14px;">
                    <div style="font-weight: 600; color: #245c37; margin-bottom: 6px;">${this.escapeHtml(step.focus || 'General analysis')}</div>
                    <p style="font-size: 13px; color: #3f6b4c; margin: 0 0 8px 0; line-height: 1.5;">The database query returned 0 records, so this specific check did not find suspicious activity. Analyst verdict is skipped for this step.</p>
                    <div style="font-size: 12px; color: #3f6b4c;">Results: 0</div>
                    ${queryGeneration.expected_findings ? `<div style="font-size: 12px; color: #6c757d; margin-top: 8px;">Checked for: ${this.escapeHtml(queryGeneration.expected_findings)}</div>` : ''}
                    <details style="margin-top: 8px;">
                        <summary style="cursor: pointer; color: #198754; font-size: 12px;">Show executed Cypher query</summary>
                        <pre style="white-space: pre-wrap; word-break: break-word; background: #fff; border: 1px solid #cfe9d8; border-radius: 4px; padding: 8px; font-size: 12px; margin: 8px 0 0 0;">${this.escapeHtml(step.query || '')}</pre>
                    </details>
                </div>

                <div style="border: 1px solid #d8dee9; border-radius: 6px; padding: 12px; background: #fff; margin-bottom: 14px;">
                    <h6 style="color: #495057; margin-bottom: 8px;"><i class="fas fa-route" style="margin-right: 6px;"></i>Next Step</h6>
                    <p style="font-size: 13px; color: #555; line-height: 1.5; margin: 0 0 10px 0;">${this.escapeHtml(nextStep.explanation)}</p>
                    <textarea id="hitl-next-context" style="display: none;">${this.escapeHtml(nextStep.context)}</textarea>
                    <details style="margin-bottom: 12px;">
                        <summary style="cursor: pointer; color: #667eea; font-size: 12px;">Show proposed Cypher query</summary>
                        <pre style="white-space: pre-wrap; word-break: break-word; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 8px; font-size: 12px; margin: 8px 0 0 0;">${this.escapeHtml(nextStep.cypherQuery || nextStep.context)}</pre>
                    </details>

                    <div style="display: grid; gap: 10px;">
                        <button class="btn btn-primary" onclick="aiAssistant.submitHitlNoResultDecision('continue')" style="background: #667eea; border-color: #667eea; text-align: left; padding: 12px;">
                            <strong><i class="fas fa-forward" style="margin-right: 6px;"></i>Continue with next step</strong>
                            <span style="display: block; font-size: 12px; opacity: 0.9; margin-top: 3px;">Use the AI agent proposal and continue the investigation.</span>
                        </button>
                        <div style="border: 1px solid #dee2e6; border-radius: 6px; padding: 10px; background: #f8f9fa;">
                            <label for="hitl-no-result-custom-instruction" style="display: block; font-weight: 600; color: #495057; margin-bottom: 6px;">Instruct AI agent instead</label>
                            <textarea id="hitl-no-result-custom-instruction" rows="3" placeholder="Describe what the AI agent should investigate next." style="width: 100%; border: 1px solid #ced4da; border-radius: 6px; padding: 9px; font-size: 12px; resize: vertical; margin-bottom: 8px;"></textarea>
                            <button class="btn btn-outline-secondary" onclick="aiAssistant.submitHitlNoResultDecision('override')" style="width: 100%; text-align: left;">
                                <strong><i class="fas fa-pen" style="margin-right: 6px;"></i>Run my instruction instead</strong>
                            </button>
                        </div>
                        <button class="btn btn-outline-danger" onclick="aiAssistant.submitHitlNoResultDecision('end')" style="text-align: left; padding: 10px;">
                            <strong><i class="fas fa-stop" style="margin-right: 6px;"></i>End investigation</strong>
                            <span style="display: block; font-size: 12px; margin-top: 3px;">Stop now and generate the final report.</span>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    async submitHitlNoResultDecision(decision) {
        if (!this.hitlSession || !this.hitlSession.pending_step) return;

        if (decision === 'end') {
            await this.finalizeHitlInvestigation('analyst_requested_stop');
            return;
        }

        const proposedNext = (document.getElementById('hitl-next-context')?.value || '').trim();
        const customInstruction = (document.getElementById('hitl-no-result-custom-instruction')?.value || '').trim();

        if (decision === 'override' && !customInstruction) {
            alert('Please provide a free-form investigation instruction before overriding the proposed next step.');
            return;
        }

        const feedback = {
            iteration: this.hitlSession.pending_step.iteration,
            verdict: 'unknown',
            verdict_label: 'unknown',
            analyst_prompt: '',
            llm_next_step: proposedNext,
            next_step_decision: decision === 'override' ? 'override' : 'accept',
            accepted_next_step: decision !== 'override',
            custom_instruction: decision === 'override' ? customInstruction : '',
            reviewed_at: new Date().toISOString()
        };

        this.hitlSession.analyst_feedback.push(feedback);

        const stepContext = decision === 'override' ? customInstruction : (proposedNext || this.hitlSession.context);
        if (decision !== 'override') {
            this.hitlSession.context = stepContext;
        }
        await this.runHitlStep(stepContext, feedback);
    }

    async submitHitlDecision(decision) {
        if (!this.hitlSession || !this.hitlSession.pending_step) return;

        const verdictInput = document.querySelector('input[name="hitl-verdict"]:checked');
        const verdict = verdictInput?.value || 'unknown';
        const verdictLabels = {
            malicious: 'malicious',
            benign: 'benign',
            unknown: 'unknown'
        };
        const analystPrompt = (document.getElementById('hitl-analyst-prompt')?.value || '').trim();
        const proposedNext = (document.getElementById('hitl-next-context')?.value || '').trim();
        const customInstruction = (document.getElementById('hitl-custom-instruction')?.value || '').trim();

        if (decision === 'override' && !customInstruction) {
            alert('Please provide a free-form investigation instruction before rejecting the proposed next step.');
            return;
        }

        const feedback = {
            iteration: this.hitlSession.pending_step.iteration,
            verdict: verdict,
            verdict_label: verdictLabels[verdict],
            analyst_prompt: analystPrompt,
            llm_next_step: proposedNext,
            next_step_decision: decision,
            accepted_next_step: decision === 'accept',
            custom_instruction: decision === 'override' ? customInstruction : '',
            reviewed_at: new Date().toISOString()
        };

        this.hitlSession.analyst_feedback.push(feedback);

        if (decision === 'end') {
            await this.finalizeHitlInvestigation('analyst_requested_stop', feedback);
            return;
        }

        const stepContext = decision === 'override' ? customInstruction : (proposedNext || this.hitlSession.context);
        if (decision !== 'override') {
            this.hitlSession.context = stepContext;
        }
        await this.runHitlStep(stepContext, feedback);
    }

    async finalizeHitlInvestigation(completionReason = 'analyst_requested_stop', analystFeedback = null) {
        if (!this.hitlSession) return;

        this.agentRunning = true;
        this.showPanel();
        this.showHitlFinalizing();

        try {
            const response = await fetch('/api/ai/agent-finalize', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCsrfToken(),
                },
                body: JSON.stringify({
                    hitl_session_id: this.hitlSession.id,
                    analyst_feedback: analystFeedback,
                    completion_reason: completionReason
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            if (result.success === false) {
                this.displayError(`Finalize Error: ${result.error}`);
                return;
            }

            this.displayAgentResults(result);
            this.hitlSession = null;
        } catch (error) {
            console.error('Error finalizing HITL AI agent investigation:', error);
            this.displayError(`Failed to finalize analyst-in-the-loop investigation: ${error.message}`);
        } finally {
            this.agentRunning = false;
        }
    }

    showHitlFinalizing() {
        const content = document.getElementById('analysis-content');
        content.innerHTML = `
            <div class="agent-loading" style="text-align: center; padding: 40px 20px;">
                <div class="agent-spinner" style="border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 54px; height: 54px; animation: spin 1s linear infinite; margin: 0 auto 20px;"></div>
                <h5 style="color: #667eea; margin-bottom: 12px;">Generating Final Report</h5>
                <p style="margin: 0; color: #667eea; font-size: 15px; font-weight: 500;">Incorporating Analyst feedback...</p>
            </div>
            <style>
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            </style>
        `;
    }

    showAgentLoading() {
        const content = document.getElementById('analysis-content');
        content.innerHTML = `
            <div class="agent-loading" style="text-align: center; padding: 40px 20px;">
                <div class="agent-spinner" style="border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 60px; height: 60px; animation: spin 1s linear infinite; margin: 0 auto 20px;"></div>
                <h5 style="color: #667eea; margin-bottom: 15px;"><i class="fas fa-robot" style="margin-right: 8px;"></i>AI Agent Investigation</h5>
                <p style="margin: 0; color: #667eea; font-size: 16px; font-weight: 500;">Autonomous threat detection in progress...</p>
                <p style="margin: 10px 0 0 0; color: #999; font-size: 14px;">The agent is generating queries, analyzing data, and hunting for threats.</p>
            </div>
            <style>
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            </style>
        `;
    }

    displayAgentProgress(result) {
        const content = document.getElementById('analysis-content');
        const investigationHistory = (result.investigation_history || [])
            .filter(step => !this.isInternalFreeformFallbackStep(step));
        const maxIterations = result.max_iterations || '?';
        const statusText = result.status === 'finalizing'
            ? 'Generating the final investigation report...'
            : 'Investigation is continuing with the next step...';

        const timelineHtml = investigationHistory.length > 0
            ? investigationHistory.map((step, index) => {
                const hasError = Boolean(step.analysis?.error);
                const threatDetected = Boolean(step.analysis?.threat_detected);
                const iconColor = hasError ? '#ffc107' : (threatDetected ? '#dc3545' : '#28a745');
                const icon = hasError ? 'fas fa-exclamation-triangle' : (threatDetected ? 'fas fa-exclamation-circle' : 'fas fa-check-circle');
                const visibleErrorText = this.getVisibleErrorText(step.error);
                const resultText = hasError
                    ? 'Query failed'
                    : `Query returned ${this.escapeHtml(step.results_count || 0)} results`;
                const verdictText = hasError
                    ? (visibleErrorText || 'Query error recorded in server logs')
                    : (threatDetected ? 'Threat detected' : 'No threat detected');

                return `
                    <div style="margin-bottom: 14px; padding-left: 28px; position: relative;">
                        <div style="position: absolute; left: 0; top: 2px; width: 18px; height: 18px; border-radius: 50%; background: ${iconColor}; display: flex; align-items: center; justify-content: center;">
                            <i class="${icon}" style="color: white; font-size: 10px;"></i>
                        </div>
                        <div style="font-size: 13px; color: #495057; font-weight: 600;">Step ${index + 1}: ${this.escapeHtml(step.focus || 'General analysis')}</div>
                        <div style="font-size: 12px; color: #6c757d; margin-top: 3px;">${resultText} - ${this.escapeHtml(verdictText)}</div>
                    </div>
                `;
            }).join('')
            : '<p style="font-size: 13px; color: #6c757d; margin: 0;">Preparing the first investigation step...</p>';

        content.innerHTML = `
            <div class="agent-progress">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 14px;">
                    <div class="agent-spinner" style="border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 32px; height: 32px; animation: spin 1s linear infinite; flex: 0 0 auto;"></div>
                    <div>
                        <h5 style="color: #667eea; margin: 0 0 4px 0;"><i class="fas fa-robot" style="margin-right: 8px;"></i>AI Agent Investigation</h5>
                        <div style="font-size: 13px; color: #6c757d;">${this.escapeHtml(statusText)}</div>
                    </div>
                </div>
                <div style="background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 12px; margin-bottom: 14px;">
                    <div style="display: flex; justify-content: space-between; gap: 10px; font-size: 13px; color: #495057;">
                        <strong>Completed steps</strong>
                        <span>${investigationHistory.length} / ${this.escapeHtml(maxIterations)}</span>
                    </div>
                    <div style="font-size: 12px; color: #6c757d; margin-top: 5px;">Threats found: ${this.escapeHtml(result.threats_discovered || 0)}</div>
                </div>
                <div style="border-top: 1px solid #dee2e6; padding-top: 12px;">
                    ${timelineHtml}
                </div>
            </div>
            <style>
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            </style>
        `;
    }

    displayAgentResults(result) {
        const content = document.getElementById('analysis-content');
        
        const investigationHistory = (result.investigation_history || [])
            .filter(step => !this.isInternalFreeformFallbackStep(step));
        const discoveredThreats = result.discovered_threats || [];
        const finalReport = result.final_report || {};
        const analystFeedback = result.analyst_feedback || [];
        const safeFinalSummary = this.escapeHtml(finalReport.analysis_summary || '');
        const safeFinalSummaryPreview = this.escapeHtml((finalReport.analysis_summary || '').substring(0, 300));
        
        let html = `
            <div class="agent-results">
                <div class="agent-summary mb-4">
                    <h5 style="color: #667eea; margin-bottom: 15px;">
                        <i class="fas fa-robot"></i> AI Agent Investigation Complete
                    </h5>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="metric-card" style="background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%); border: 1px solid #2196f3; border-radius: 8px; padding: 15px; text-align: center; box-shadow: 0 2px 8px rgba(33, 150, 243, 0.15); margin-bottom: 10px;">
                                <div class="metric-icon" style="color: #1976d2; font-size: 24px; margin-bottom: 8px;">
                                    <i class="fas fa-list-ol"></i>
                                </div>
                                <div class="metric-value" style="font-size: 28px; font-weight: bold; color: #1976d2; margin-bottom: 5px;">${investigationHistory.length}</div>
                                <div class="metric-label" style="font-size: 13px; color: #555; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Investigation Steps</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="metric-card" style="background: linear-gradient(135deg, ${result.threats_discovered > 0 ? '#ffebee 0%, #ffcdd2 100%' : '#e8f5e8 0%, #c8e6c8 100%'}); border: 1px solid ${result.threats_discovered > 0 ? '#f44336' : '#4caf50'}; border-radius: 8px; padding: 15px; text-align: center; box-shadow: 0 2px 8px rgba(${result.threats_discovered > 0 ? '244, 67, 54' : '76, 175, 80'}, 0.15); margin-bottom: 10px;">
                                <div class="metric-icon" style="color: ${result.threats_discovered > 0 ? '#d32f2f' : '#388e3c'}; font-size: 24px; margin-bottom: 8px;">
                                    <i class="fas ${result.threats_discovered > 0 ? 'fa-exclamation-triangle' : 'fa-shield-alt'}"></i>
                                </div>
                                <div class="metric-value" style="font-size: 28px; font-weight: bold; color: ${result.threats_discovered > 0 ? '#d32f2f' : '#388e3c'}; margin-bottom: 5px;">${result.threats_discovered || 0}</div>
                                <div class="metric-label" style="font-size: 13px; color: #555; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Threats Found</div>
                            </div>
                        </div>
                    </div>
                </div>
        `;

        if (result.analyst_in_loop) {
            html += `
                <div class="hitl-summary mb-4" style="background: #f8f9fa; border: 1px solid #d8dee9; border-radius: 6px; padding: 12px;">
                    <h6 style="margin: 0 0 8px 0; color: #495057;">
                        <i class="fas fa-user-check" style="margin-right: 6px;"></i>
                        Analysis Summary
                    </h6>
                    <div style="font-size: 13px; color: #555;">
                        Reviews: ${analystFeedback.length} | Completion: ${this.escapeHtml(result.completion_reason || 'completed')}
                    </div>
                    ${analystFeedback.length > 0 ? `
                        <div style="margin-top: 8px; display: flex; flex-direction: column; gap: 6px;">
                            ${analystFeedback.map(item => `
                                <div style="font-size: 12px; border-left: 3px solid #667eea; padding-left: 8px;">
                                    Step ${this.escapeHtml(item.iteration)}: <strong>${this.escapeHtml(item.verdict_label || item.verdict)}</strong>
                                    ${item.next_step_decision ? ` | Next: ${this.escapeHtml(item.next_step_decision)}` : ''}
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            `;
        }

        // Add Generate Sigma Rules button for High/Critical risk levels (placed prominently after summary metrics)
        const riskLevel = finalReport.overall_risk_level || result.risk_level || 'low';
        if (riskLevel.toLowerCase() === 'high' || riskLevel.toLowerCase() === 'critical') {
            html += `
                <div class="sigma-generation-section mb-4" style="background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%); border: 2px solid #667eea; border-radius: 12px; padding: 16px;">
                    <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
                        <div style="flex: 1; min-width: 200px;">
                            <h6 style="margin: 0 0 4px 0; color: #667eea; font-weight: 600;">
                                <i class="fas fa-file-code" style="margin-right: 6px;"></i>
                                Sigma Rule Generation Available
                            </h6>
                            <small style="color: #6c757d;">Create detection rules based on discovered threats</small>
                        </div>
                        <button id="btn-generate-sigma" class="btn" 
                                onclick="aiAssistant.generateSigmaRules()" 
                                style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: none; color: white; padding: 10px 20px; border-radius: 8px; font-weight: 600; display: flex; align-items: center; gap: 8px; white-space: nowrap;">
                            <i class="fas fa-magic"></i>
                            Generate Sigma Rules
                        </button>
                    </div>
                </div>
            `;
        }

        // Display analysis summary if available
        if (finalReport.analysis_summary) {
            const summaryCollapsibleId = 'agent-summary-' + Date.now();
            const isLongSummary = finalReport.analysis_summary.length > 300;
            
            html += `
                <div class="analysis-summary mb-4">
                    <h6 style="margin-bottom: 10px; color: #333; font-weight: 600; display: flex; align-items: center;">
                        <i class="fas fa-file-alt" style="margin-right: 8px; color: #667eea;"></i>
                        Investigation Summary
                        ${isLongSummary ? `<button onclick="toggleContent('${summaryCollapsibleId}')" style="margin-left: auto; background: none; border: 1px solid #ccc; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 12px;">
                            <i class="fas fa-expand-alt"></i> <span id="${summaryCollapsibleId}-toggle-text">Expand</span>
                        </button>` : ''}
                    </h6>
                    <div style="background: #f8f9fa; padding: 12px; border-radius: 4px; border-left: 4px solid #667eea;">
                        ${isLongSummary ? `
	                            <div id="${summaryCollapsibleId}-preview" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px;">${safeFinalSummaryPreview}...</div>
	                            <div id="${summaryCollapsibleId}-full" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px; display: none;">${safeFinalSummary}</div>
	                        ` : `<p style="margin: 0; line-height: 1.6; color: #555; font-size: 14px;">${safeFinalSummary}</p>`}
                    </div>
                </div>
            `;
        }

        // Display discovered threats
        if (discoveredThreats.length > 0) {
            html += `
                <div class="threats-section mb-4">
                    <h6 style="color: #dc3545; margin-bottom: 15px;">
                        <i class="fas fa-exclamation-triangle"></i> Discovered Threats
                    </h6>
            `;
            
            discoveredThreats.forEach((threat, index) => {
                const severityColor = this.getThreatSeverityColor(threat.severity);
                const safeThreatType = this.escapeHtml(threat.threat_type || 'Unknown');
                const safeSeverity = this.escapeHtml(threat.severity || 'Unknown');
                const safeDescription = this.escapeHtml(threat.description || 'No description available');
                const safeEvidence = Array.isArray(threat.evidence) ? threat.evidence.map(e => this.escapeHtml(e)) : [];
                html += `
                    <div class="threat-item mb-3" style="border-left: 4px solid ${severityColor}; background: #f8f9fa; padding: 15px; border-radius: 0 6px 6px 0;">
                        <div class="threat-header">
                            <h6 style="margin: 0; color: ${severityColor};">
                                Threat #${index + 1}: ${safeThreatType}
                                <span class="badge" style="background-color: ${severityColor}; margin-left: 10px;">${safeSeverity}</span>
                            </h6>
                        </div>
                        <p style="margin: 10px 0; color: #555;">${safeDescription}</p>
                        ${safeEvidence.length > 0 ? `
                            <div class="evidence">
                                <strong>Evidence:</strong>
                                <ul style="margin: 5px 0 0 20px;">
                                    ${safeEvidence.map(e => `<li>${e}</li>`).join('')}
                                </ul>
                            </div>
                        ` : ''}
                    </div>
                `;
            });
            
            html += '</div>';
        } else {
            html += `
                <div class="no-threats mb-4">
                    <div class="alert alert-success">
                        <i class="fas fa-shield-alt"></i> No immediate threats detected by the AI agent.
                    </div>
                </div>
            `;
        }

        // Display investigation timeline
        if (investigationHistory.length > 0) {
            html += `
                <div class="investigation-timeline mb-4">
                    <h6 style="color: #495057; margin-bottom: 15px;">
                        <i class="fas fa-search"></i> Investigation Timeline
                    </h6>
                    <div class="timeline">
            `;
            
            investigationHistory.forEach((step, index) => {
                const hasError = step.analysis?.error || false;
                const visibleErrorText = this.getVisibleErrorText(step.error);
                const showErrorDetails = hasError && visibleErrorText;
                const threatDetected = step.analysis?.threat_detected || false;
                
                let iconColor, icon, statusText;
                
                if (hasError) {
                    iconColor = '#ffc107';
                    icon = 'fas fa-exclamation-triangle';
                    statusText = visibleErrorText ? `Query Error: ${visibleErrorText}` : 'Query Error';
                } else if (threatDetected) {
                    iconColor = '#dc3545';
                    icon = 'fas fa-exclamation-circle';
                    statusText = 'Threat Detected!';
                } else {
                    iconColor = '#28a745';
                    icon = 'fas fa-check-circle';
                    statusText = 'No threats found';
                }
                
                html += `
                    <div class="timeline-item" style="margin-bottom: 20px; padding-left: 30px; position: relative;">
                        <div class="timeline-icon" style="position: absolute; left: 0; top: 0; width: 20px; height: 20px; border-radius: 50%; background: ${iconColor}; display: flex; align-items: center; justify-content: center;">
                            <i class="${icon}" style="color: white; font-size: 12px;"></i>
                        </div>
	                        <div class="timeline-content">
	                            <h6 style="margin: 0 0 5px 0; color: #495057;">Step ${index + 1}: ${this.escapeHtml(step.focus || 'General analysis')}</h6>
	                            <p style="margin: 0; font-size: 14px; color: #6c757d;">
	                                ${hasError ? `Query failed with error` : `Query returned ${this.escapeHtml(step.results_count || 0)} results`}
	                                <span style="color: ${iconColor}; font-weight: bold;"> - ${this.escapeHtml(statusText)}</span>
                            </p>
                            ${showErrorDetails ? `
                                <div style="margin-top: 8px; padding: 8px; background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; font-size: 12px;">
                                    <strong>Error Details:</strong> ${this.escapeHtml(visibleErrorText)}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
            });
            
            html += '</div></div>';
        }

        html += '</div>';
        
        content.innerHTML = html;
        this.currentAnalysis = result;
        this.updateHistoryButtonVisibility();
    }

    getThreatSeverityColor(severity) {
        const colors = {
            'low': '#28a745',
            'medium': '#ffc107',
            'high': '#fd7e14',
            'critical': '#dc3545'
        };
        return colors[severity] || '#6c757d';
    }

    async generateSigmaRules() {
        if (!this.currentAnalysis) {
            alert('No analysis result available. Please run AI analysis first.');
            return;
        }

        const btn = document.getElementById('btn-generate-sigma');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating Sigma Rules...';
        }

        try {
            const response = await fetch('/api/ai/generate-sigma-rules', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCsrfToken(),
                },
                body: JSON.stringify({
                    analysis_result: this.currentAnalysis
                })
            });

            const result = await response.json();
            
            if (result.success && result.sigma_rules && result.sigma_rules.length > 0) {
                this.displaySigmaRules(result);
            } else {
                this.displaySigmaError(result.message || 'Failed to generate Sigma rules');
            }
        } catch (error) {
            console.error('Sigma rule generation error:', error);
            this.displaySigmaError('Error: ' + error.message);
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-file-code"></i> Generate Sigma Rules';
            }
        }
    }

    displaySigmaRules(result) {
        const sigmaRules = result.sigma_rules || [];
        
        // Remove existing modal if any (to ensure fresh state)
        let existingModal = document.getElementById('sigma-rules-modal');
        if (existingModal) {
            existingModal.remove();
        }
        
        // Create new modal for displaying Sigma rules
        let modal = document.createElement('div');
        modal.id = 'sigma-rules-modal';
        modal.className = 'modal fade';
        modal.tabIndex = -1;
        modal.innerHTML = `
            <div class="modal-dialog modal-lg modal-dialog-scrollable">
                <div class="modal-content">
                    <div class="modal-header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                        <h5 class="modal-title">
                            <i class="fas fa-file-code"></i> Generated Sigma Rules
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body" id="sigma-rules-content">
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onclick="aiAssistant.downloadAllSigmaRules()">
                            <i class="fas fa-download"></i> Download All
                        </button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        
        // Build content
        let content = `
            <div class="sigma-rules-container">
                <div class="alert alert-success mb-4">
                    <i class="fas fa-check-circle"></i> 
	                    ${this.escapeHtml(result.message || `Generated ${sigmaRules.length} Sigma rule(s)`)}
                </div>
        `;
        
        this.generatedSigmaRules = sigmaRules;
        
        sigmaRules.forEach((rule, index) => {
            const threatColor = this.getThreatSeverityColor(
                rule.yaml_content?.includes('level: critical') ? 'critical' : 
                rule.yaml_content?.includes('level: high') ? 'high' : 'medium'
            );
            
            content += `
                <div class="card mb-3" style="border-left: 4px solid ${threatColor};">
                    <div class="card-header d-flex justify-content-between align-items-center" style="background: #f8f9fa;">
                        <div>
	                            <strong>${this.escapeHtml(rule.rule_name || `Rule ${index + 1}`)}</strong>
	                            <span class="badge bg-info ms-2">${this.escapeHtml(rule.threat_type || 'Unknown')}</span>
                        </div>
                        <button class="btn btn-sm btn-outline-primary" onclick="aiAssistant.downloadSigmaRule(${index})">
                            <i class="fas fa-download"></i> Download
                        </button>
                    </div>
                    <div class="card-body">
	                        <p class="card-text text-muted mb-3">${this.escapeHtml(rule.description || 'No description')}</p>
                        ${rule.target_event_ids && rule.target_event_ids.length > 0 ? `
                            <p class="mb-2">
                                <strong>Target Event IDs:</strong> 
	                                ${rule.target_event_ids.map(id => `<span class="badge bg-secondary me-1">${this.escapeHtml(id)}</span>`).join('')}
                            </p>
                        ` : ''}
                        <div class="yaml-content" style="background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; font-size: 12px; max-height: 400px; overflow-y: auto;">
                            <pre style="margin: 0; white-space: pre-wrap;">${this.escapeHtml(rule.yaml_content || 'No YAML content')}</pre>
                        </div>
                    </div>
                </div>
            `;
        });
        
        content += '</div>';
        
        document.getElementById('sigma-rules-content').innerHTML = content;
        
        // Show modal
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();
    }

    displaySigmaError(message) {
        // Remove existing modal if any (to ensure fresh state)
        let existingModal = document.getElementById('sigma-rules-modal');
        if (existingModal) {
            existingModal.remove();
        }
        
        // Create new modal for error message
        let modal = document.createElement('div');
        modal.id = 'sigma-rules-modal';
        modal.className = 'modal fade';
        modal.tabIndex = -1;
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header" style="background: #dc3545; color: white;">
                        <h5 class="modal-title">
                            <i class="fas fa-exclamation-triangle"></i> Sigma Rule Generation Failed
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body" id="sigma-rules-content">
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        
        document.getElementById('sigma-rules-content').innerHTML = `
            <div class="alert alert-danger">
	                <i class="fas fa-exclamation-circle"></i> ${this.escapeHtml(message)}
            </div>
        `;
        
        // Show modal
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();
    }

    downloadSigmaRule(index) {
        if (!this.generatedSigmaRules || !this.generatedSigmaRules[index]) {
            alert('Rule not found');
            return;
        }
        
        const rule = this.generatedSigmaRules[index];
        const filename = (rule.rule_name || `sigma_rule_${index + 1}`).replace(/[^a-zA-Z0-9_-]/g, '_') + '.yml';
        const content = rule.yaml_content || '';
        
        this.downloadFile(filename, content);
    }

    downloadAllSigmaRules() {
        if (!this.generatedSigmaRules || this.generatedSigmaRules.length === 0) {
            alert('No rules to download');
            return;
        }
        
        // Combine all rules into one file with YAML document separators
        let combinedContent = '# Generated Sigma Rules by LogonTracer AI Analysis\n';
        combinedContent += `# Generated: ${new Date().toISOString()}\n`;
        combinedContent += `# Total Rules: ${this.generatedSigmaRules.length}\n\n`;
        
        this.generatedSigmaRules.forEach((rule, index) => {
            // Add YAML document separator (required for multi-document YAML files)
            combinedContent += `---\n`;
            combinedContent += `# Rule ${index + 1}: ${rule.rule_name || 'Unnamed'}\n`;
            combinedContent += (rule.yaml_content || '') + '\n\n';
        });
        
        const filename = `logontracer_sigma_rules_${new Date().toISOString().slice(0, 10)}.yml`;
        this.downloadFile(filename, combinedContent);
    }

    downloadFile(filename, content) {
        const blob = new Blob([content], { type: 'text/yaml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    getRiskLevelColor(level) {
        const colors = {
            'low': '#28a745',
            'medium': '#ffc107',
            'high': '#fd7e14',
            'critical': '#dc3545'
        };
        return colors[level] || '#6c757d';
    }
}

// Initialize AI Assistant after DOM is loaded
let aiAssistant;

document.addEventListener('DOMContentLoaded', function() {
    aiAssistant = new AISecurityAssistant();
});

// Global function for hiding panel (used in onclick handlers)
function hideAIPanel() {
    if (typeof aiAssistant !== 'undefined' && aiAssistant) {
        aiAssistant.hidePanel();
    }
}

// Helper function to determine query type from Cypher query string
function getQueryTypeFromString(queryStr) {
    const queryLower = queryStr.toLowerCase();
    
    if (queryLower.includes('user.rights = "system"') || queryLower.includes('nprivilege.*system')) {
        return 'system_privileges';
    }
    if (queryLower.includes('event.logintype = 10') || queryLower.includes('logontype.*10')) {
        return 'rdp_logon';
    }
    if (queryLower.includes('event.logintype = 3') || queryLower.includes('logontype.*3')) {
        return 'network_logon';
    }
    if (queryLower.includes('event.logintype = 4') || queryLower.includes('logontype.*4')) {
        return 'batch_logon';
    }
    if (queryLower.includes('event.logintype = 5') || queryLower.includes('logontype.*5')) {
        return 'service_logon';
    }
    if (queryLower.includes('authname = "ntlm"') || queryLower.includes('authname.*ntlm')) {
        return 'ntlm_logon';
    }
    if (queryLower.includes('status =~ ".*0f"') || queryLower.includes('ms14068')) {
        return 'ms14068_exploit';
    }
    if (queryLower.includes('dcsync') || queryLower.includes('dcshadow')) {
        return 'dc_attacks';
    }
    if (queryLower.includes('created') || queryLower.includes('deleted')) {
        return 'user_changes';
    }
    if (queryLower.includes('shortestpath') || queryLower.includes('allshortestpaths')) {
        return 'attack_path';
    }
    
    return 'general_analysis';
}

// Global function for toggling collapsible content
function toggleContent(elementId) {
    const preview = document.getElementById(elementId + '-preview');
    const full = document.getElementById(elementId + '-full');
    const toggleText = document.getElementById(elementId + '-toggle-text');
    
    if (preview && full) {
        if (preview.style.display === 'none') {
            // Show preview, hide full
            preview.style.display = 'block';
            full.style.display = 'none';
            if (toggleText) toggleText.textContent = 'Expand';
        } else {
            // Show full, hide preview
            preview.style.display = 'none';
            full.style.display = 'block';
            if (toggleText) toggleText.textContent = 'Collapse';
        }
    }
}

// Global function for showing AI history from main interface
function showAIHistory() {
    if (typeof aiAssistant !== 'undefined' && aiAssistant) {
        aiAssistant.showLastAnalysis();
    } else {
        console.warn('AI Assistant not initialized');
    }
}
