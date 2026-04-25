import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
    Container, Typography, Paper, Box, CircularProgress,
    Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
    Chip, Button, Grid, LinearProgress, Tooltip, IconButton,
    alpha, useTheme
} from '@mui/material';
import {
    RssFeed, PlayArrow, Stop, Refresh,
    Circle, OpenInNew
} from '@mui/icons-material';
import api from '../api/client';

// ─── Constants ───────────────────────────────────────────────
const PYPI_RSS_URL = 'https://pypi.org/rss/updates.xml';

// ─── Types ───────────────────────────────────────────────────

interface FeedEntry {
    guid: string;
    package_name: string;
    package_version: string;
    title: string;
    link: string;
    published: string;
    summary: string;
    anomaly_score: number;
    risk_level: string;
    triggered_rules: string[];
    processed_at: string;
}

interface MonitorStatus {
    running: boolean;
    feed_url: string;
    poll_interval_seconds: number;
    entries_in_buffer: number;
    buffer_capacity: number;
}

// ─── Auto-Refresh Interval ──────────────────────────────────
const AUTO_REFRESH_MS = 30_000;

// ─── Component ──────────────────────────────────────────────

export const Monitor: React.FC = () => {
    const theme = useTheme();

    const [entries, setEntries] = useState<FeedEntry[]>([]);
    const [status, setStatus] = useState<MonitorStatus | null>(null);
    const [loading, setLoading] = useState(true);
    const [countdown, setCountdown] = useState(AUTO_REFRESH_MS / 1000);
    const [actionLoading, setActionLoading] = useState(false);

    const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

    // ─── Data Fetching ───────────────────────────────────────

    const loadData = useCallback(async (silent = false) => {
        if (!silent) setLoading(true);
        try {
            const [feedRes, statusRes] = await Promise.all([
                api.monitor.getFeed(100),
                api.monitor.getStatus(),
            ]);
            setEntries(feedRes.entries || []);
            setStatus(statusRes);
        } catch (err) {
            console.error('Failed to load monitor data:', err);
        } finally {
            if (!silent) setLoading(false);
        }
    }, []);

    // Initial load
    useEffect(() => {
        loadData();
    }, [loadData]);

    // Auto-refresh every 30 seconds
    useEffect(() => {
        setCountdown(AUTO_REFRESH_MS / 1000);

        timerRef.current = setInterval(() => {
            setCountdown(prev => {
                if (prev <= 1) {
                    loadData(true);
                    return AUTO_REFRESH_MS / 1000;
                }
                return prev - 1;
            });
        }, 1000);

        return () => {
            if (timerRef.current) clearInterval(timerRef.current);
        };
    }, [loadData]);

    // ─── Actions ─────────────────────────────────────────────

    const handleStart = async () => {
        setActionLoading(true);
        try {
            await api.monitor.start();
            await loadData(true);
        } catch (err) {
            console.error('Failed to start monitor:', err);
        } finally {
            setActionLoading(false);
        }
    };

    const handleStop = async () => {
        setActionLoading(true);
        try {
            await api.monitor.stop();
            await loadData(true);
        } catch (err) {
            console.error('Failed to stop monitor:', err);
        } finally {
            setActionLoading(false);
        }
    };

    const handleManualRefresh = () => {
        setCountdown(AUTO_REFRESH_MS / 1000);
        loadData(true);
    };

    // ─── Risk Color Helpers ──────────────────────────────────

    const getRiskColor = (risk: string): string => {
        switch (risk.toLowerCase()) {
            case 'critical': return theme.palette.error.main;
            case 'high': return theme.palette.error.light;
            case 'medium': return theme.palette.warning.main;
            case 'low': return theme.palette.success.main;
            default: return theme.palette.text.secondary;
        }
    };

    const getRiskChipColor = (risk: string): 'error' | 'warning' | 'success' | 'info' | 'default' => {
        switch (risk.toLowerCase()) {
            case 'critical': return 'error';
            case 'high': return 'error';
            case 'medium': return 'warning';
            case 'low': return 'success';
            default: return 'default';
        }
    };

    const isHighRisk = (risk: string) => ['critical', 'high'].includes(risk.toLowerCase());

    const getScoreBarColor = (score: number): 'error' | 'warning' | 'info' | 'success' => {
        if (score >= 75) return 'error';
        if (score >= 50) return 'warning';
        if (score >= 25) return 'info';
        return 'success';
    };

    // ─── Stats ───────────────────────────────────────────────

    const criticalCount = entries.filter(e => e.risk_level === 'critical').length;
    const highCount = entries.filter(e => e.risk_level === 'high').length;
    const mediumCount = entries.filter(e => e.risk_level === 'medium').length;
    const lowCount = entries.filter(e => e.risk_level === 'low').length;

    // ─── Render ──────────────────────────────────────────────

    return (
        <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>

            {/* ─── Header ────────────────────────────────────────── */}
            <Box mb={4} display="flex" alignItems="center" justifyContent="space-between">
                <Box display="flex" alignItems="center" gap={2}>
                    <RssFeed
                        sx={{
                            fontSize: 40,
                            color: status?.running ? 'warning.main' : 'text.disabled',
                            animation: status?.running ? 'pulse 2s ease-in-out infinite' : 'none',
                            '@keyframes pulse': {
                                '0%, 100%': { opacity: 1 },
                                '50%': { opacity: 0.4 },
                            },
                        }}
                    />
                    <Box>
                        <Typography variant="h4" fontWeight="bold" color="text.primary">
                            Real-Time Feed Monitor
                        </Typography>
                        <Typography variant="subtitle1" color="text.secondary">
                            Live PyPI package publishes — scored and tracked in real time.
                        </Typography>
                    </Box>
                </Box>

                <Box display="flex" alignItems="center" gap={1}>
                    <Chip
                        icon={<Circle sx={{ fontSize: 10 }} />}
                        label={status?.running ? 'LIVE' : 'STOPPED'}
                        size="small"
                        color={status?.running ? 'success' : 'default'}
                        variant="outlined"
                        sx={{ fontWeight: 'bold' }}
                    />
                    <Typography variant="caption" color="text.secondary" sx={{ minWidth: 60, textAlign: 'right' }}>
                        {countdown}s
                    </Typography>
                    <Tooltip title="Refresh now">
                        <IconButton size="small" onClick={handleManualRefresh}>
                            <Refresh fontSize="small" />
                        </IconButton>
                    </Tooltip>
                </Box>
            </Box>

            {/* ─── Control Bar + Stats ────────────────────────────── */}
            <Grid container spacing={2} mb={3}>
                {/* Controls */}
                <Grid item xs={12} md={4}>
                    <Paper
                        sx={{
                            p: 2.5,
                            borderRadius: 2,
                            height: '100%',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 2,
                        }}
                    >
                        <Typography variant="subtitle2" color="text.secondary" fontWeight="bold">
                            Monitor Controls
                        </Typography>
                        <Box display="flex" gap={1}>
                            <Button
                                variant="contained"
                                color="success"
                                startIcon={<PlayArrow />}
                                onClick={handleStart}
                                disabled={actionLoading || !!status?.running}
                                size="small"
                                sx={{ flex: 1 }}
                            >
                                Start
                            </Button>
                            <Button
                                variant="contained"
                                color="error"
                                startIcon={<Stop />}
                                onClick={handleStop}
                                disabled={actionLoading || !status?.running}
                                size="small"
                                sx={{ flex: 1 }}
                            >
                                Stop
                            </Button>
                        </Box>
                        {status && (
                            <Box>
                                <Typography variant="caption" color="text.secondary">
                                    Buffer: {status.entries_in_buffer} / {status.buffer_capacity} &nbsp;·&nbsp;
                                    Poll: every {status.poll_interval_seconds}s
                                </Typography>
                                <LinearProgress
                                    variant="determinate"
                                    value={(status.entries_in_buffer / status.buffer_capacity) * 100}
                                    sx={{ mt: 0.5, borderRadius: 1, height: 6 }}
                                />
                            </Box>
                        )}
                    </Paper>
                </Grid>

                {/* Risk Summary Cards */}
                {[
                    { label: 'Critical', count: criticalCount, color: theme.palette.error.main },
                    { label: 'High', count: highCount, color: theme.palette.error.light },
                    { label: 'Medium', count: mediumCount, color: theme.palette.warning.main },
                    { label: 'Low', count: lowCount, color: theme.palette.success.main },
                ].map(({ label, count, color }) => (
                    <Grid item xs={6} md={2} key={label}>
                        <Paper
                            sx={{
                                p: 2.5,
                                borderRadius: 2,
                                height: '100%',
                                borderLeft: `4px solid ${color}`,
                                display: 'flex',
                                flexDirection: 'column',
                                justifyContent: 'center',
                            }}
                        >
                            <Typography variant="caption" color="text.secondary" fontWeight="bold" textTransform="uppercase">
                                {label}
                            </Typography>
                            <Typography variant="h4" fontWeight="bold" sx={{ color }}>
                                {count}
                            </Typography>
                        </Paper>
                    </Grid>
                ))}
            </Grid>

            {/* ─── Feed Table ─────────────────────────────────────── */}
            <TableContainer
                component={Paper}
                sx={{
                    borderRadius: 2,
                    boxShadow: 2,
                    maxHeight: 'calc(100vh - 380px)',
                    overflow: 'auto',
                }}
            >
                <Table stickyHeader sx={{ minWidth: 800 }}>
                    <TableHead>
                        <TableRow>
                            <TableCell sx={{ bgcolor: 'background.paper', fontWeight: 'bold' }}>Package</TableCell>
                            <TableCell sx={{ bgcolor: 'background.paper', fontWeight: 'bold' }}>Version</TableCell>
                            <TableCell sx={{ bgcolor: 'background.paper', fontWeight: 'bold', minWidth: 140 }}>Risk Score</TableCell>
                            <TableCell sx={{ bgcolor: 'background.paper', fontWeight: 'bold' }}>Risk Level</TableCell>
                            <TableCell sx={{ bgcolor: 'background.paper', fontWeight: 'bold' }}>Rules Triggered</TableCell>
                            <TableCell sx={{ bgcolor: 'background.paper', fontWeight: 'bold' }}>Published</TableCell>
                            <TableCell sx={{ bgcolor: 'background.paper', fontWeight: 'bold' }}>Processed</TableCell>
                            <TableCell sx={{ bgcolor: 'background.paper', fontWeight: 'bold' }} align="right">Link</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {loading ? (
                            <TableRow>
                                <TableCell colSpan={8} align="center" sx={{ py: 8 }}>
                                    <CircularProgress />
                                    <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                                        Loading feed data...
                                    </Typography>
                                </TableCell>
                            </TableRow>
                        ) : entries.length === 0 ? (
                            <TableRow>
                                <TableCell colSpan={8} align="center" sx={{ py: 8 }}>
                                    <RssFeed sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
                                    <Typography color="text.secondary">
                                        No feed entries yet. The monitor will populate this table as packages are published to PyPI.
                                    </Typography>
                                </TableCell>
                            </TableRow>
                        ) : (
                            entries.map((entry) => {
                                const highRisk = isHighRisk(entry.risk_level);
                                return (
                                    <TableRow
                                        key={entry.guid}
                                        hover
                                        sx={{
                                            bgcolor: highRisk
                                                ? alpha(theme.palette.error.main, 0.06)
                                                : 'inherit',
                                            borderLeft: highRisk
                                                ? `3px solid ${theme.palette.error.main}`
                                                : '3px solid transparent',
                                            transition: 'background-color 0.3s ease',
                                        }}
                                    >
                                        {/* Package Name */}
                                        <TableCell>
                                            <Typography
                                                variant="body2"
                                                fontWeight="bold"
                                                sx={{
                                                    color: highRisk ? 'error.main' : 'text.primary',
                                                }}
                                            >
                                                {entry.package_name}
                                            </Typography>
                                        </TableCell>

                                        {/* Version */}
                                        <TableCell>
                                            <Chip
                                                label={entry.package_version}
                                                size="small"
                                                variant="outlined"
                                                sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                                            />
                                        </TableCell>

                                        {/* Risk Score Bar */}
                                        <TableCell>
                                            <Box display="flex" alignItems="center" gap={1}>
                                                <Box sx={{ flex: 1, minWidth: 60 }}>
                                                    <LinearProgress
                                                        variant="determinate"
                                                        value={Math.min(entry.anomaly_score, 100)}
                                                        color={getScoreBarColor(entry.anomaly_score)}
                                                        sx={{
                                                            height: 8,
                                                            borderRadius: 4,
                                                            bgcolor: alpha(getRiskColor(entry.risk_level), 0.12),
                                                        }}
                                                    />
                                                </Box>
                                                <Typography
                                                    variant="body2"
                                                    fontWeight="bold"
                                                    sx={{
                                                        minWidth: 36,
                                                        textAlign: 'right',
                                                        color: getRiskColor(entry.risk_level),
                                                    }}
                                                >
                                                    {entry.anomaly_score.toFixed(1)}
                                                </Typography>
                                            </Box>
                                        </TableCell>

                                        {/* Risk Level Badge */}
                                        <TableCell>
                                            <Chip
                                                label={entry.risk_level.toUpperCase()}
                                                size="small"
                                                color={getRiskChipColor(entry.risk_level)}
                                                sx={{
                                                    fontWeight: 'bold',
                                                    animation: highRisk ? 'riskPulse 2s ease-in-out infinite' : 'none',
                                                    '@keyframes riskPulse': {
                                                        '0%, 100%': { boxShadow: `0 0 0 0 ${alpha(theme.palette.error.main, 0.4)}` },
                                                        '50%': { boxShadow: `0 0 0 6px ${alpha(theme.palette.error.main, 0)}` },
                                                    },
                                                }}
                                            />
                                        </TableCell>

                                        {/* Triggered Rules */}
                                        <TableCell>
                                            {entry.triggered_rules.length > 0 ? (
                                                <Box display="flex" flexWrap="wrap" gap={0.5}>
                                                    {entry.triggered_rules.slice(0, 3).map((rule) => (
                                                        <Chip
                                                            key={rule}
                                                            label={rule}
                                                            size="small"
                                                            variant="outlined"
                                                            color="warning"
                                                            sx={{ fontSize: '0.7rem', height: 22 }}
                                                        />
                                                    ))}
                                                    {entry.triggered_rules.length > 3 && (
                                                        <Chip
                                                            label={`+${entry.triggered_rules.length - 3}`}
                                                            size="small"
                                                            sx={{ fontSize: '0.7rem', height: 22 }}
                                                        />
                                                    )}
                                                </Box>
                                            ) : (
                                                <Typography variant="caption" color="text.disabled">—</Typography>
                                            )}
                                        </TableCell>

                                        {/* Published */}
                                        <TableCell>
                                            <Typography variant="body2" color="text.secondary">
                                                {entry.published
                                                    ? new Date(entry.published).toLocaleTimeString()
                                                    : '—'}
                                            </Typography>
                                        </TableCell>

                                        {/* Processed */}
                                        <TableCell>
                                            <Typography variant="body2" color="text.secondary">
                                                {new Date(entry.processed_at).toLocaleTimeString()}
                                            </Typography>
                                        </TableCell>

                                        {/* PyPI Link */}
                                        <TableCell align="right">
                                            <Tooltip title="View on PyPI">
                                                <IconButton
                                                    size="small"
                                                    color="primary"
                                                    href={entry.link}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                >
                                                    <OpenInNew fontSize="small" />
                                                </IconButton>
                                            </Tooltip>
                                        </TableCell>
                                    </TableRow>
                                );
                            })
                        )}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* ─── Footer Info ────────────────────────────────────── */}
            {!loading && entries.length > 0 && (
                <Box mt={2} display="flex" justifyContent="space-between" alignItems="center">
                    <Typography variant="caption" color="text.secondary">
                        Showing {entries.length} entries · Auto-refreshes every {AUTO_REFRESH_MS / 1000}s
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                        Feed: {status?.feed_url || PYPI_RSS_URL}
                    </Typography>
                </Box>
            )}
        </Container>
    );
};

export default Monitor;
