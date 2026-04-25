import React, { useState, useRef, useCallback, useEffect } from 'react';
import {
    Box, Typography, TextField, Button, Select, MenuItem,
    FormControl, InputLabel, CircularProgress, Paper, Chip,
    IconButton, Divider, LinearProgress, Alert,
} from '@mui/material';
import {
    Search, Close, BugReport, Fingerprint,
    FiberManualRecord, AccountTree, Hub
} from '@mui/icons-material';
import ForceGraph2D from 'react-force-graph-2d';
import api from '../api/client';

// ─── Types ───────────────────────────────────────────────────

interface GraphNode {
    id: string;
    name: string;
    version: string;
    ecosystem: string;
    risk_score: number;
    is_direct: boolean;
    x?: number;
    y?: number;
}

interface GraphLink {
    source: string | GraphNode;
    target: string | GraphNode;
    risk_score: number;
}

interface GraphData {
    nodes: GraphNode[];
    links: GraphLink[];
}

// ─── Helpers ─────────────────────────────────────────────────

const getRiskColor = (score: number): string => {
    if (score >= 70) return '#E24B4A';   // red
    if (score >= 40) return '#EF9F27';   // orange
    return '#639922';                    // green
};

const getRiskLabel = (score: number): string => {
    if (score >= 70) return 'High Risk';
    if (score >= 40) return 'Medium Risk';
    return 'Clean';
};

const getRiskChipColor = (score: number): 'error' | 'warning' | 'success' => {
    if (score >= 70) return 'error';
    if (score >= 40) return 'warning';
    return 'success';
};

// ─── Component ───────────────────────────────────────────────

export const GraphView: React.FC = () => {
    // Search state
    const [packageName, setPackageName] = useState('');
    const [ecosystem, setEcosystem] = useState('pypi');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    // Graph data
    const [graphData, setGraphData] = useState<GraphData | null>(null);
    const graphRef = useRef<any>(null);

    // Side panel
    const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
    const [panelOpen, setPanelOpen] = useState(false);

    // CVE state
    const [cveLoading, setCveLoading] = useState(false);
    const [cveResults, setCveResults] = useState<any>(null);
    const [cveError, setCveError] = useState('');

    // Typosquat state
    const [typoLoading, setTypoLoading] = useState(false);
    const [typoResult, setTypoResult] = useState<any>(null);
    const [typoError, setTypoError] = useState('');

    // Container size for responsive graph
    const containerRef = useRef<HTMLDivElement>(null);
    const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

    // Recent Scans
    const [recentScans, setRecentScans] = useState<any[]>([]);

    useEffect(() => {
        const fetchHistory = async () => {
            try {
                const res = await api.dependencies.getHistory();
                setRecentScans(res?.scans || []);
            } catch (err) {
                console.error("Failed to fetch recent scans:", err);
            }
        };
        fetchHistory();
    }, []);

    useEffect(() => {
        const updateSize = () => {
            if (containerRef.current) {
                const rect = containerRef.current.getBoundingClientRect();
                setDimensions({
                    width: rect.width,
                    height: rect.height,
                });
            }
        };
        updateSize();
        window.addEventListener('resize', updateSize);
        return () => window.removeEventListener('resize', updateSize);
    }, [graphData]);

    // ─── Load Graph ──────────────────────────────────────────

    const handleLoadGraph = async (forcedPackage?: any) => {
        const nameToLoad = typeof forcedPackage === 'string' ? forcedPackage.trim() : packageName.trim();
        
        if (!nameToLoad) {
            setError('Please enter a package name.');
            return;
        }

        if (typeof forcedPackage === 'string') {
            setPackageName(nameToLoad);
        }

        setLoading(true);
        setError('');
        setGraphData(null);
        setSelectedNode(null);
        setPanelOpen(false);

        try {
            const raw = await api.dependencies.getGraph(ecosystem, nameToLoad);

            // react-force-graph-2d requires nodes to have an `id` field
            const transformed = {
                nodes: (raw.nodes || []).map((n: any) => ({
                    ...n,
                    id: n.name,           // required by force-graph
                    label: n.name,
                })),
                links: (raw.links || []).map((l: any) => ({
                    ...l,
                    source: l.source,     // already matches node id
                    target: l.target,
                })),
            };

            setGraphData(transformed);

            // Auto-zoom to fit after data loads
            setTimeout(() => {
                if (graphRef.current) {
                    graphRef.current.zoomToFit(400, 60);
                }
            }, 500);
        } catch (err: any) {
            const detail = err.response?.data?.detail;
            setError(
                typeof detail === 'string'
                    ? detail
                    : err.message || 'Failed to load graph data.'
            );
        } finally {
            setLoading(false);
        }
    };

    // ─── Node Click ──────────────────────────────────────────

    const handleNodeClick = useCallback((node: any) => {
        setSelectedNode(node as GraphNode);
        setPanelOpen(true);
        setCveResults(null);
        setCveError('');
        setTypoResult(null);
        setTypoError('');
    }, []);

    const handleClosePanel = () => {
        setPanelOpen(false);
        setSelectedNode(null);
    };

    // ─── CVE Check ───────────────────────────────────────────

    const handleCheckCves = async () => {
        if (!selectedNode) return;
        setCveLoading(true);
        setCveError('');
        setCveResults(null);

        try {
            const data = await api.cve.checkPackage(
                selectedNode.name,
                selectedNode.ecosystem || ecosystem
            );
            setCveResults(data);
        } catch (err: any) {
            setCveError(err.response?.data?.detail || err.message || 'CVE check failed.');
        } finally {
            setCveLoading(false);
        }
    };

    // ─── Typosquat Check ─────────────────────────────────────

    const handleCheckTyposquat = async () => {
        if (!selectedNode) return;
        setTypoLoading(true);
        setTypoError('');
        setTypoResult(null);

        try {
            const data = await api.typosquat.checkSingle(
                selectedNode.name,
                selectedNode.ecosystem || ecosystem
            );
            setTypoResult(data);
        } catch (err: any) {
            setTypoError(err.response?.data?.detail || err.message || 'Typosquat check failed.');
        } finally {
            setTypoLoading(false);
        }
    };

    // ─── Canvas Rendering ────────────────────────────────────

    const paintNode = useCallback((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const n = node as GraphNode;
        const radius = n.is_direct ? 8 : 5;
        const color = getRiskColor(n.risk_score || 0);
        const label = n.name;
        const fontSize = Math.max(12 / globalScale, 1.5);

        // Glow effect for high-risk nodes
        if (n.risk_score >= 70) {
            ctx.beginPath();
            ctx.arc(node.x!, node.y!, radius + 4, 0, 2 * Math.PI);
            ctx.fillStyle = 'rgba(226, 75, 74, 0.15)';
            ctx.fill();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x!, node.y!, radius, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();

        // Border
        ctx.strokeStyle = n.is_direct ? '#ffffff' : 'rgba(255,255,255,0.3)';
        ctx.lineWidth = n.is_direct ? 2 / globalScale : 0.5 / globalScale;
        ctx.stroke();

        // Label
        ctx.font = `${n.is_direct ? 'bold ' : ''}${fontSize}px Inter, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = 'rgba(255,255,255,0.9)';
        ctx.fillText(label, node.x!, node.y! + radius + 2);
    }, []);

    const paintLink = useCallback((link: any, ctx: CanvasRenderingContext2D) => {
        const start = link.source;
        const end = link.target;
        if (!start || !end || typeof start.x !== 'number') return;

        ctx.beginPath();
        ctx.moveTo(start.x, start.y);
        ctx.lineTo(end.x, end.y);
        ctx.strokeStyle = getRiskColor(link.risk_score || 0);
        ctx.globalAlpha = 0.3;
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.globalAlpha = 1;
    }, []);

    // ─── Render ──────────────────────────────────────────────

    const panelWidth = 380;

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 100px)', mx: -3, mt: -3 }}>
            {/* ─── Search Bar ─────────────────────────────── */}
            <Paper
                elevation={0}
                sx={{
                    px: 3, py: 2,
                    borderBottom: 1,
                    borderColor: 'divider',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 2,
                    flexWrap: 'wrap',
                    bgcolor: 'background.paper',
                }}
            >
                <Hub color="primary" sx={{ fontSize: 32 }} />
                <Typography variant="h6" fontWeight="bold" sx={{ mr: 1 }}>
                    Dependency Graph
                </Typography>

                <FormControl size="small" sx={{ minWidth: 130 }}>
                    <InputLabel id="graph-eco-label">Ecosystem</InputLabel>
                    <Select
                        labelId="graph-eco-label"
                        value={ecosystem}
                        label="Ecosystem"
                        onChange={(e: { target: { value: string } }) => setEcosystem(e.target.value)}
                    >
                        <MenuItem value="pypi">PyPI</MenuItem>
                        <MenuItem value="npm">npm</MenuItem>
                    </Select>
                </FormControl>

                <FormControl size="small" sx={{ minWidth: 160 }}>
                    <InputLabel id="recent-scans-label">Recent Scans</InputLabel>
                    <Select
                        labelId="recent-scans-label"
                        value=""
                        label="Recent Scans"
                        onChange={(e) => {
                            const val = e.target.value as string;
                            if (val) {
                                handleLoadGraph(val);
                            }
                        }}
                    >
                        <MenuItem value="" sx={{ display: 'none' }}><em>Select a project</em></MenuItem>
                        {recentScans.map((scan: any) => (
                            <MenuItem key={scan.id} value={scan.project_name || scan.package_name}>
                                {scan.project_name || scan.package_name}
                            </MenuItem>
                        ))}
                    </Select>
                </FormControl>

                <TextField
                    size="small"
                    label="Package Name"
                    placeholder={ecosystem === 'pypi' ? 'requests' : 'express'}
                    value={packageName}
                    onChange={(e) => setPackageName(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleLoadGraph(); }}
                    sx={{ minWidth: 220, flexGrow: 1, maxWidth: 400 }}
                />

                <Button
                    variant="contained"
                    onClick={() => handleLoadGraph()}
                    disabled={loading}
                    startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <Search />}
                    sx={{ fontWeight: 'bold', px: 3 }}
                >
                    {loading ? 'Loading...' : 'Load Graph'}
                </Button>
            </Paper>

            {error && (
                <Alert severity="error" sx={{ mx: 2, mt: 1 }} onClose={() => setError('')}>
                    {error}
                </Alert>
            )}

            {/* ─── Graph + Side Panel ─────────────────────── */}
            <Box sx={{ flexGrow: 1, display: 'flex', position: 'relative', overflow: 'hidden' }}>

                {/* Graph Area */}
                <Box
                    ref={containerRef}
                    sx={{
                        flexGrow: 1,
                        bgcolor: '#0a0e1a',
                        position: 'relative',
                        transition: 'margin-right 0.3s ease',
                        mr: panelOpen ? `${panelWidth}px` : 0,
                    }}
                >
                    {/* Empty State */}
                    {(!graphData || graphData.nodes.length === 0) && !loading && (
                        <Box
                            display="flex" flexDirection="column"
                            alignItems="center" justifyContent="center"
                            height="100%" color="rgba(255,255,255,0.4)"
                        >
                            <AccountTree sx={{ fontSize: 100, mb: 2, opacity: 0.3 }} />
                            <Typography variant="h5" fontWeight="bold" sx={{ opacity: 0.6, mb: 1, textAlign: 'center' }}>
                                {graphData && graphData.nodes.length === 0 ? "No graph data found" : "No Graph Loaded"}
                            </Typography>
                            <Typography sx={{ opacity: 0.4, textAlign: 'center', maxWidth: 400 }}>
                                {graphData && graphData.nodes.length === 0 
                                    ? "No graph data found. Scan this package first from the Dependency Scanner." 
                                    : "Search for a package above to visualize its dependency graph."}
                            </Typography>
                        </Box>
                    )}

                    {/* Loading Overlay */}
                    {loading && (
                        <Box
                            display="flex" flexDirection="column"
                            alignItems="center" justifyContent="center"
                            height="100%" color="white"
                        >
                            <CircularProgress size={64} thickness={3} sx={{ mb: 3 }} />
                            <Typography variant="h6" fontWeight="bold" sx={{ opacity: 0.8 }}>
                                Building dependency graph...
                            </Typography>
                            <Typography sx={{ opacity: 0.5, mt: 1 }}>
                                Querying Neo4j for {packageName} on {ecosystem.toUpperCase()}
                            </Typography>
                        </Box>
                    )}

                    {/* Force Graph */}
                    {graphData && graphData.nodes.length > 0 && !loading && (
                        <ForceGraph2D
                            ref={graphRef}
                            graphData={graphData}
                            width={dimensions.width - (panelOpen ? panelWidth : 0)}
                            height={dimensions.height}
                            nodeCanvasObject={paintNode}
                            nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
                                const radius = (node as GraphNode).is_direct ? 8 : 5;
                                ctx.beginPath();
                                ctx.arc(node.x!, node.y!, radius + 4, 0, 2 * Math.PI);
                                ctx.fillStyle = color;
                                ctx.fill();
                            }}
                            linkCanvasObject={paintLink}
                            onNodeClick={handleNodeClick}
                            cooldownTicks={120}
                            d3AlphaDecay={0.02}
                            d3VelocityDecay={0.3}
                            backgroundColor="#0a0e1a"
                            enableZoomInteraction={true}
                            enablePanInteraction={true}
                        />
                    )}

                    {/* ─── Color Legend ────────────────────── */}
                    {graphData && graphData.nodes.length > 0 && !loading && (
                        <Paper
                            sx={{
                                position: 'absolute',
                                bottom: 20,
                                left: 20,
                                px: 2.5, py: 1.5,
                                bgcolor: 'rgba(10, 14, 26, 0.85)',
                                backdropFilter: 'blur(12px)',
                                borderRadius: 2,
                                border: '1px solid rgba(255,255,255,0.08)',
                            }}
                        >
                            <Typography variant="caption" fontWeight="bold" sx={{ color: 'rgba(255,255,255,0.5)', mb: 1, display: 'block' }}>
                                RISK LEVEL
                            </Typography>
                            <Box display="flex" flexDirection="column" gap={0.5}>
                                <Box display="flex" alignItems="center" gap={1}>
                                    <FiberManualRecord sx={{ fontSize: 12, color: '#E24B4A' }} />
                                    <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.75)' }}>
                                        High Risk (≥ 70)
                                    </Typography>
                                </Box>
                                <Box display="flex" alignItems="center" gap={1}>
                                    <FiberManualRecord sx={{ fontSize: 12, color: '#EF9F27' }} />
                                    <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.75)' }}>
                                        Medium (≥ 40)
                                    </Typography>
                                </Box>
                                <Box display="flex" alignItems="center" gap={1}>
                                    <FiberManualRecord sx={{ fontSize: 12, color: '#639922' }} />
                                    <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.75)' }}>
                                        Clean (&lt; 40)
                                    </Typography>
                                </Box>
                            </Box>
                        </Paper>
                    )}

                    {/* ─── Stats Legend ────────────────────── */}
                    {graphData && graphData.nodes.length > 0 && !loading && (
                        <Paper
                            sx={{
                                position: 'absolute',
                                bottom: 20,
                                right: 20,
                                px: 2.5, py: 1.5,
                                bgcolor: 'rgba(10, 14, 26, 0.85)',
                                backdropFilter: 'blur(12px)',
                                borderRadius: 2,
                                border: '1px solid rgba(255,255,255,0.08)',
                            }}
                        >
                            <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.9)' }}>
                                <strong>{graphData.nodes.length}</strong> nodes · <strong>{graphData.links.length}</strong> edges
                            </Typography>
                        </Paper>
                    )}
                </Box>

                {/* ─── Side Panel ─────────────────────────── */}
                <Paper
                    elevation={8}
                    sx={{
                        position: 'absolute',
                        top: 0,
                        right: 0,
                        width: panelWidth,
                        height: '100%',
                        transform: panelOpen ? 'translateX(0)' : `translateX(${panelWidth}px)`,
                        transition: 'transform 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                        display: 'flex',
                        flexDirection: 'column',
                        borderLeft: 1,
                        borderColor: 'divider',
                        overflowY: 'auto',
                        bgcolor: 'background.paper',
                        zIndex: 10,
                    }}
                >
                    {selectedNode && (
                        <>
                            {/* Panel Header */}
                            <Box sx={{
                                px: 2.5, py: 2,
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                borderBottom: 1,
                                borderColor: 'divider',
                                bgcolor: 'action.hover',
                            }}>
                                <Box>
                                    <Typography variant="h6" fontWeight="bold" sx={{ lineHeight: 1.2 }}>
                                        {selectedNode.name}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                        v{selectedNode.version || 'latest'}
                                    </Typography>
                                </Box>
                                <IconButton size="small" onClick={handleClosePanel}>
                                    <Close />
                                </IconButton>
                            </Box>

                            {/* Panel Body */}
                            <Box sx={{ p: 2.5, display: 'flex', flexDirection: 'column', gap: 2 }}>
                                {/* Chips Row */}
                                <Box display="flex" gap={1} flexWrap="wrap">
                                    <Chip
                                        label={selectedNode.ecosystem?.toUpperCase() || ecosystem.toUpperCase()}
                                        size="small"
                                        color="primary"
                                        variant="outlined"
                                    />
                                    <Chip
                                        label={selectedNode.is_direct ? 'Direct' : 'Transitive'}
                                        size="small"
                                        color={selectedNode.is_direct ? 'primary' : 'default'}
                                        variant={selectedNode.is_direct ? 'filled' : 'outlined'}
                                    />
                                </Box>

                                {/* Risk Score */}
                                <Box>
                                    <Typography variant="overline" fontWeight="bold" color="text.secondary">
                                        Risk Score
                                    </Typography>
                                    <Box display="flex" alignItems="center" gap={2} mt={0.5}>
                                        <Box sx={{ flexGrow: 1 }}>
                                            <LinearProgress
                                                variant="determinate"
                                                value={Math.min(selectedNode.risk_score || 0, 100)}
                                                sx={{
                                                    height: 10,
                                                    borderRadius: 5,
                                                    bgcolor: 'action.hover',
                                                    '& .MuiLinearProgress-bar': {
                                                        bgcolor: getRiskColor(selectedNode.risk_score || 0),
                                                        borderRadius: 5,
                                                    },
                                                }}
                                            />
                                        </Box>
                                        <Chip
                                            label={`${selectedNode.risk_score ?? 0} — ${getRiskLabel(selectedNode.risk_score || 0)}`}
                                            size="small"
                                            color={getRiskChipColor(selectedNode.risk_score || 0)}
                                        />
                                    </Box>
                                </Box>

                                <Divider />

                                {/* Action Buttons */}
                                <Box display="flex" flexDirection="column" gap={1.5}>
                                    <Button
                                        variant="outlined"
                                        color="warning"
                                        fullWidth
                                        startIcon={cveLoading ? <CircularProgress size={16} /> : <BugReport />}
                                        onClick={handleCheckCves}
                                        disabled={cveLoading}
                                        sx={{ fontWeight: 'bold', justifyContent: 'flex-start' }}
                                    >
                                        {cveLoading ? 'Checking...' : 'Check CVEs'}
                                    </Button>

                                    <Button
                                        variant="outlined"
                                        color="secondary"
                                        fullWidth
                                        startIcon={typoLoading ? <CircularProgress size={16} /> : <Fingerprint />}
                                        onClick={handleCheckTyposquat}
                                        disabled={typoLoading}
                                        sx={{ fontWeight: 'bold', justifyContent: 'flex-start' }}
                                    >
                                        {typoLoading ? 'Checking...' : 'Check Typosquat'}
                                    </Button>
                                </Box>

                                {/* CVE Results */}
                                {cveError && (
                                    <Alert severity="error" variant="outlined" sx={{ fontSize: 13 }}>
                                        {cveError}
                                    </Alert>
                                )}
                                {cveResults && (
                                    <Box>
                                        <Typography variant="overline" fontWeight="bold" color="text.secondary">
                                            CVE Results
                                        </Typography>
                                        {(cveResults.vulnerabilities || cveResults.cves || []).length === 0 ? (
                                            <Alert severity="success" variant="outlined" sx={{ mt: 0.5, fontSize: 13 }}>
                                                No known CVEs found for this package.
                                            </Alert>
                                        ) : (
                                            <Box sx={{ mt: 0.5, display: 'flex', flexDirection: 'column', gap: 1 }}>
                                                {(cveResults.vulnerabilities || cveResults.cves || []).map((cve: any, i: number) => (
                                                    <Paper
                                                        key={i}
                                                        variant="outlined"
                                                        sx={{
                                                            p: 1.5,
                                                            borderLeft: 4,
                                                            borderColor: cve.severity === 'CRITICAL' ? 'error.main'
                                                                : cve.severity === 'HIGH' ? 'warning.main'
                                                                : 'info.main',
                                                        }}
                                                    >
                                                        <Typography variant="body2" fontWeight="bold">
                                                            {cve.cve_id || cve.id}
                                                        </Typography>
                                                        <Chip
                                                            label={cve.severity || 'UNKNOWN'}
                                                            size="small"
                                                            color={
                                                                cve.severity === 'CRITICAL' ? 'error'
                                                                    : cve.severity === 'HIGH' ? 'warning'
                                                                    : 'info'
                                                            }
                                                            sx={{ mt: 0.5, mb: 0.5 }}
                                                        />
                                                        <Typography variant="caption" color="text.secondary" display="block">
                                                            {cve.description?.slice(0, 160) || 'No description'}
                                                            {(cve.description?.length || 0) > 160 ? '…' : ''}
                                                        </Typography>
                                                    </Paper>
                                                ))}
                                            </Box>
                                        )}
                                    </Box>
                                )}

                                {/* Typosquat Results */}
                                {typoError && (
                                    <Alert severity="error" variant="outlined" sx={{ fontSize: 13 }}>
                                        {typoError}
                                    </Alert>
                                )}
                                {typoResult && (
                                    <Box>
                                        <Typography variant="overline" fontWeight="bold" color="text.secondary">
                                            Typosquat Check
                                        </Typography>
                                        {typoResult.is_suspicious ? (
                                            <Alert severity="warning" variant="outlined" sx={{ mt: 0.5, fontSize: 13 }}>
                                                <Typography variant="body2" fontWeight="bold">
                                                    ⚠ Possible typosquat detected
                                                </Typography>
                                                <Typography variant="caption" display="block">
                                                    Similar to: <strong>{typoResult.closest_match || typoResult.similar_to}</strong>
                                                </Typography>
                                                <Typography variant="caption" display="block">
                                                    Distance: {typoResult.distance} · Severity: {typoResult.severity}
                                                </Typography>
                                            </Alert>
                                        ) : (
                                            <Alert severity="success" variant="outlined" sx={{ mt: 0.5, fontSize: 13 }}>
                                                Package name appears legitimate. No typosquat matches found.
                                            </Alert>
                                        )}
                                    </Box>
                                )}
                            </Box>
                        </>
                    )}
                </Paper>
            </Box>
        </Box>
    );
};

export default GraphView;
