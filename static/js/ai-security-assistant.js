class AISecurityAssistant {
    constructor() {
        this.isAnalyzing = false;
        this.currentAnalysis = null;
        this.isEnabled = false;
        this.analysisPanel = null;
        this.agentRunning = false;

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
                <small style="opacity: 0.9; font-size: 12px;">Powered by OpenAI</small>
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
        const isConnectionError = parsedAnalysis.summary && parsedAnalysis.summary.includes('connect to OpenAI');
        const isTimeoutError = parsedAnalysis.summary && parsedAnalysis.summary.includes('timed out');
        
        if (isQuotaError) {
            this.displayQuotaError(parsedAnalysis);
            return;
        }
        
        if (isAuthError || isConnectionError || isTimeoutError) {
            this.displayServiceError(parsedAnalysis);
            return;
        }
        
        this.displayFormattedAnalysis(parsedAnalysis);
        this.updateHistoryButtonVisibility();
    }

    displayRawAnalysis(rawText) {
        const content = document.getElementById('analysis-content');
        const collapsibleId = 'raw-analysis-' + Date.now();
        const isLongText = rawText.length > 500;
        const displayText = isLongText ? rawText.substring(0, 500) + '...' : rawText;
        
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
                        <div id="${collapsibleId}-preview" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px; font-family: monospace; white-space: pre-wrap; ${isLongText ? '' : 'display: none;'}">${displayText}</div>
                        <div id="${collapsibleId}-full" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px; font-family: monospace; white-space: pre-wrap; max-height: 400px; overflow-y: auto; ${isLongText ? 'display: none;' : ''}">${this.formatJSON(rawText)}</div>
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
        
        content.innerHTML = `
            <div class="analysis-result">
                <div class="risk-assessment" style="margin-bottom: 20px;">
                    <div class="risk-badge" style="background: ${riskColor}; color: white; padding: 10px 15px; border-radius: 6px; display: flex; align-items: center; font-weight: 600;">
                        <i class="${riskIcon}" style="margin-right: 8px;"></i>
                        ${analysis.risk_level} Risk Level
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
                            <div id="${summaryCollapsibleId}-preview" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px;">${analysis.summary.substring(0, 300)}...</div>
                            <div id="${summaryCollapsibleId}-full" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px; display: none;">${analysis.summary}</div>
                        ` : `<p style="margin: 0; line-height: 1.6; color: #555; font-size: 14px;">${analysis.summary}</p>`}
                    </div>
                </div>

                ${analysis.key_findings && analysis.key_findings.length > 0 ? `
                <div class="key-findings" style="margin-bottom: 20px;">
                    <h6 style="margin-bottom: 10px; color: #333; font-weight: 600; display: flex; align-items: center;">
                        <i class="fas fa-search" style="margin-right: 8px; color: #28a745;"></i>
                        Key Findings
                    </h6>
                    <ul style="margin: 0; padding-left: 0; list-style: none;">
                        ${analysis.key_findings.map(finding => 
                            `<li style="margin-bottom: 8px; padding: 8px 12px; background: #e8f5e8; border-radius: 4px; font-size: 14px; border-left: 3px solid #28a745;">
                                <i class="fas fa-check-circle" style="margin-right: 8px; color: #28a745;"></i>${finding}
                            </li>`
                        ).join('')}
                    </ul>
                </div>
                ` : ''}

                ${analysis.security_concerns && analysis.security_concerns.length > 0 ? `
                <div class="security-concerns" style="margin-bottom: 20px;">
                    <h6 style="margin-bottom: 10px; color: #dc3545; font-weight: 600; display: flex; align-items: center;">
                        <i class="fas fa-exclamation-triangle" style="margin-right: 8px; color: #dc3545;"></i>
                        Security Concerns
                    </h6>
                    <ul style="margin: 0; padding-left: 0; list-style: none;">
                        ${analysis.security_concerns.map(concern => 
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
                        ${analysis.recommendations.map(rec => 
                            `<li style="margin-bottom: 8px; padding: 8px 12px; background: #e6f3ff; border-radius: 4px; font-size: 14px; border-left: 3px solid #17a2b8;">
                                <i class="fas fa-arrow-right" style="margin-right: 8px; color: #17a2b8;"></i>${rec}
                            </li>`
                        ).join('')}
                    </ul>
                </div>

                ${analysis.analysis_metadata ? `
                <div class="analysis-metadata" style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #eee;">
                    <small style="color: #6c757d; font-size: 11px;">
                        Analysis by ${analysis.analysis_metadata.model} • Query: ${analysis.analysis_metadata.query_type}
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
        const content = document.getElementById('analysis-content');
        content.innerHTML = `
            <div class="error-message" style="text-align: center; padding: 30px 20px;">
                <i class="fas fa-exclamation-triangle" style="font-size: 32px; color: #dc3545; margin-bottom: 15px;"></i>
                <h6 style="color: #dc3545; margin-bottom: 10px;">Analysis Failed</h6>
                <p style="margin: 0; color: #6c757d; font-size: 14px; line-height: 1.5;">${message}</p>
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
                <h5 style="color: #ff6b6b; margin-bottom: 15px;">OpenAI API Quota Exceeded</h5>
                <p style="color: #666; margin-bottom: 20px; font-size: 14px; line-height: 1.5;">
                    Your OpenAI API usage has exceeded the current plan limits. 
                    AI-powered analysis is temporarily unavailable.
                </p>
                
                <div class="error-details" style="background: #fff5f5; border: 1px solid #fed7d7; border-radius: 6px; padding: 15px; margin: 20px 0; text-align: left;">
                    <h6 style="color: #c53030; margin-bottom: 10px; display: flex; align-items: center;">
                        <i class="fas fa-info-circle" style="margin-right: 8px;"></i>
                        What you can do:
                    </h6>
                    <ul style="margin: 0; padding-left: 20px; color: #666; font-size: 13px;">
                        ${analysis.recommendations.map(rec => `<li style="margin-bottom: 5px;">${rec}</li>`).join('')}
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
                <p style="margin: 0; color: #6c757d; font-size: 14px; line-height: 1.5; margin-bottom: 20px;">${analysis.summary}</p>
                
                <div class="error-recommendations" style="background: #f8f9fa; border-radius: 6px; padding: 15px; margin: 15px 0; text-align: left;">
                    <h6 style="color: #495057; margin-bottom: 10px;">Recommended Actions:</h6>
                    <ul style="margin: 0; padding-left: 20px; color: #666; font-size: 13px;">
                        ${analysis.recommendations.map(rec => `<li style="margin-bottom: 5px;">${rec}</li>`).join('')}
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
    async runAgentDetection(initialContext = "Detect suspicious logon behavior in Active Directory") {
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
                    context: initialContext
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
            
            // Display agent results
            this.displayAgentResults(result);
            
        } catch (error) {
            console.error('Error running AI agent detection:', error);
            this.displayError(`Failed to run AI agent detection: ${error.message}`);
        } finally {
            this.agentRunning = false;
        }
    }

    showAgentLoading() {
        const content = document.getElementById('analysis-content');
        content.innerHTML = `
            <div class="agent-loading" style="text-align: center; padding: 40px 20px;">
                <div class="agent-spinner" style="border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 60px; height: 60px; animation: spin 1s linear infinite; margin: 0 auto 20px;"></div>
                <h5 style="color: #667eea; margin-bottom: 15px;">🤖 AI Agent Investigation</h5>
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

    displayAgentResults(result) {
        const content = document.getElementById('analysis-content');
        
        const investigationHistory = result.investigation_history || [];
        const discoveredThreats = result.discovered_threats || [];
        const finalReport = result.final_report || {};
        
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
                                <div class="metric-value" style="font-size: 28px; font-weight: bold; color: #1976d2; margin-bottom: 5px;">${result.iterations_run || 0}</div>
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
                            <div id="${summaryCollapsibleId}-preview" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px;">${finalReport.analysis_summary.substring(0, 300)}...</div>
                            <div id="${summaryCollapsibleId}-full" style="margin: 0; line-height: 1.6; color: #555; font-size: 14px; display: none;">${finalReport.analysis_summary}</div>
                        ` : `<p style="margin: 0; line-height: 1.6; color: #555; font-size: 14px;">${finalReport.analysis_summary}</p>`}
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
                html += `
                    <div class="threat-item mb-3" style="border-left: 4px solid ${severityColor}; background: #f8f9fa; padding: 15px; border-radius: 0 6px 6px 0;">
                        <div class="threat-header">
                            <h6 style="margin: 0; color: ${severityColor};">
                                Threat #${index + 1}: ${threat.threat_type || 'Unknown'}
                                <span class="badge" style="background-color: ${severityColor}; margin-left: 10px;">${threat.severity || 'Unknown'}</span>
                            </h6>
                        </div>
                        <p style="margin: 10px 0; color: #555;">${threat.description || 'No description available'}</p>
                        ${threat.evidence && threat.evidence.length > 0 ? `
                            <div class="evidence">
                                <strong>Evidence:</strong>
                                <ul style="margin: 5px 0 0 20px;">
                                    ${threat.evidence.map(e => `<li>${e}</li>`).join('')}
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
                const threatDetected = step.analysis?.threat_detected || false;
                
                let iconColor, icon, statusText;
                
                if (hasError) {
                    iconColor = '#ffc107';
                    icon = 'fas fa-exclamation-triangle';
                    statusText = `Query Error: ${step.error || 'Unknown error'}`;
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
                            <h6 style="margin: 0 0 5px 0; color: #495057;">Step ${index + 1}: ${step.focus}</h6>
                            <p style="margin: 0; font-size: 14px; color: #6c757d;">
                                ${hasError ? `Query failed with error` : `Query returned ${step.results_count} results`}
                                <span style="color: ${iconColor}; font-weight: bold;"> - ${statusText}</span>
                            </p>
                            ${hasError ? `
                                <div style="margin-top: 8px; padding: 8px; background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; font-size: 12px;">
                                    <strong>Error Details:</strong> ${step.error || 'Unknown error occurred'}
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
                    ${result.message || `Generated ${sigmaRules.length} Sigma rule(s)`}
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
                            <strong>${rule.rule_name || `Rule ${index + 1}`}</strong>
                            <span class="badge bg-info ms-2">${rule.threat_type || 'Unknown'}</span>
                        </div>
                        <button class="btn btn-sm btn-outline-primary" onclick="aiAssistant.downloadSigmaRule(${index})">
                            <i class="fas fa-download"></i> Download
                        </button>
                    </div>
                    <div class="card-body">
                        <p class="card-text text-muted mb-3">${rule.description || 'No description'}</p>
                        ${rule.target_event_ids && rule.target_event_ids.length > 0 ? `
                            <p class="mb-2">
                                <strong>Target Event IDs:</strong> 
                                ${rule.target_event_ids.map(id => `<span class="badge bg-secondary me-1">${id}</span>`).join('')}
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
                <i class="fas fa-exclamation-circle"></i> ${message}
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