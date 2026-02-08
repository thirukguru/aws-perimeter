package htmloutput

// htmlTemplate is the embedded HTML template for the security report
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Security Report - {{.AccountID}}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --critical: #f85149;
            --high: #db6d28;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
            --accent: #238636;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border-radius: 16px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
        }

        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #58a6ff, #3fb950);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .meta {
            color: var(--text-secondary);
            font-size: 0.9em;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }

        .summary-card.critical { border-left: 4px solid var(--critical); }
        .summary-card.high { border-left: 4px solid var(--high); }
        .summary-card.medium { border-left: 4px solid var(--medium); }
        .summary-card.low { border-left: 4px solid var(--low); }
        .summary-card.score { border-left: 4px solid var(--info); }

        .summary-card h3 {
            color: var(--text-secondary);
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }

        .summary-card .value {
            font-size: 2.5em;
            font-weight: 700;
        }

        .summary-card.critical .value { color: var(--critical); }
        .summary-card.high .value { color: var(--high); }
        .summary-card.medium .value { color: var(--medium); }
        .summary-card.low .value { color: var(--low); }
        .summary-card.score .value { color: var(--info); }

        .score-description {
            font-size: 0.9em;
            color: var(--text-secondary);
            margin-top: 5px;
        }

        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
        }

        .section-header {
            padding: 20px 24px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--bg-tertiary);
            transition: background 0.2s;
        }

        .section-header:hover {
            background: rgba(88, 166, 255, 0.1);
        }

        .section-header h2 {
            font-size: 1.2em;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .section-status {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }

        .section-status.critical { background: var(--critical); box-shadow: 0 0 10px var(--critical); }
        .section-status.warning { background: var(--medium); box-shadow: 0 0 10px var(--medium); }
        .section-status.good { background: var(--low); box-shadow: 0 0 10px var(--low); }

        .section-toggle {
            font-size: 1.5em;
            color: var(--text-secondary);
            transition: transform 0.3s;
        }

        .section.collapsed .section-toggle {
            transform: rotate(-90deg);
        }

        .section-content {
            padding: 0 24px 24px;
            display: block;
        }

        .section.collapsed .section-content {
            display: none;
        }

        .section-description {
            color: var(--text-secondary);
            margin-bottom: 20px;
            font-size: 0.95em;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
        }

        .findings-table th {
            text-align: left;
            padding: 12px 16px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border-color);
        }

        .findings-table td {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }

        .findings-table tr:last-child td {
            border-bottom: none;
        }

        .findings-table tr:hover {
            background: rgba(88, 166, 255, 0.05);
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-critical {
            background: rgba(248, 81, 73, 0.2);
            color: var(--critical);
            border: 1px solid var(--critical);
        }

        .severity-high {
            background: rgba(219, 109, 40, 0.2);
            color: var(--high);
            border: 1px solid var(--high);
        }

        .severity-medium {
            background: rgba(210, 153, 34, 0.2);
            color: var(--medium);
            border: 1px solid var(--medium);
        }

        .severity-low {
            background: rgba(63, 185, 80, 0.2);
            color: var(--low);
            border: 1px solid var(--low);
        }

        .resource-name {
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', monospace;
            font-size: 0.9em;
            color: var(--info);
        }

        .recommendation {
            color: var(--text-secondary);
            font-size: 0.9em;
            margin-top: 8px;
        }

        .compliance-badges {
            margin-top: 8px;
        }

        .compliance-badge {
            display: inline-block;
            padding: 2px 8px;
            margin: 2px 4px 2px 0;
            border-radius: 4px;
            font-size: 0.7em;
            font-weight: 600;
            background: rgba(88, 166, 255, 0.15);
            color: var(--info);
            border: 1px solid rgba(88, 166, 255, 0.3);
        }

        .no-findings {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }

        .no-findings .icon {
            font-size: 3em;
            margin-bottom: 15px;
        }

        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.85em;
        }

        footer a {
            color: var(--info);
            text-decoration: none;
        }

        @media (max-width: 768px) {
            header h1 { font-size: 1.8em; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .findings-table { font-size: 0.9em; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ AWS Security Report</h1>
            <p class="meta">Account: <strong>{{.AccountID}}</strong> | Generated: {{.GeneratedAt}}</p>
        </header>

        <div class="summary-grid">
            <div class="summary-card score">
                <h3>Security Score</h3>
                <div class="value">{{.Summary.SecurityScore}}</div>
                <div class="score-description">{{.Summary.ScoreDescription}}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="value">{{.Summary.CriticalCount}}</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="value">{{.Summary.HighCount}}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="value">{{.Summary.MediumCount}}</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="value">{{.Summary.LowCount}}</div>
            </div>
        </div>

        {{range .Sections}}
        <div class="section" id="{{.ID}}">
            <div class="section-header" onclick="toggleSection('{{.ID}}')">
                <h2>
                    <span class="section-status {{.Status}}"></span>
                    {{.Title}}
                    <span style="color: var(--text-secondary); font-weight: normal; font-size: 0.8em;">
                        ({{len .Findings}} findings)
                    </span>
                </h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                {{if .Description}}
                <p class="section-description">{{.Description}}</p>
                {{end}}
                {{if .Findings}}
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th style="width: 100px;">Severity</th>
                            <th style="width: 200px;">Resource</th>
                            <th>Issue</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Findings}}
                        <tr>
                            <td>
                                <span class="severity-badge severity-{{.Severity | lower}}">{{.Severity}}</span>
                            </td>
                            <td class="resource-name">{{.Resource}}</td>
                            <td>
                                <strong>{{.Title}}</strong>
                                {{if .Description}}<br>{{.Description}}{{end}}
                                {{if .Recommendation}}
                                <div class="recommendation">💡 {{.Recommendation}}</div>
                                {{end}}
                                {{if .Compliance}}
                                <div class="compliance-badges">
                                    {{range .Compliance}}<span class="compliance-badge">{{.}}</span>{{end}}
                                </div>
                                {{end}}
                            </td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
                {{else}}
                <div class="no-findings">
                    <div class="icon">✅</div>
                    <p>No findings in this category</p>
                </div>
                {{end}}
            </div>
        </div>
        {{end}}

        <footer>
            <p>Generated by <a href="https://github.com/thirukguru/aws-perimeter">aws-perimeter</a></p>
        </footer>
    </div>

    <script>
        function toggleSection(id) {
            const section = document.getElementById(id);
            section.classList.toggle('collapsed');
        }

        // Template function to lowercase strings
        function lower(str) {
            return str.toLowerCase();
        }
    </script>
</body>
</html>`
