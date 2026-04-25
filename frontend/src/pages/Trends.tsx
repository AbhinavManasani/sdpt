import React, { useEffect, useState, useCallback } from 'react';
import {
    Container, Typography, Paper, Box, Grid, Card, CardContent,
    CircularProgress, Chip, TextField, Button, Select, MenuItem,
    FormControl, InputLabel, TableContainer, Table, TableHead,
    TableRow, TableCell, TableBody, Tooltip, IconButton, Alert,
    LinearProgress, useTheme, alpha, ToggleButton, ToggleButtonGroup
} from '@mui/material';
import {
    TrendingUp, TrendingDown, Refresh, Search, ShowChart,
    Assessment, ArrowUpward, ArrowDownward, Shield,
    BarChart as BarChartIcon, PieChart as PieChartIcon,
    Timeline as TimelineIcon
} from '@mui/icons-material';
import {
    ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
    CartesianGrid, Tooltip as RechartsTooltip, PieChart,
    Pie, Cell, Legend, BarChart, Bar
} from 'recharts';
import api from '../api/client';

/* ─── Types ───────────────────────────────────────────────────── */

interface TrendStats {
    total_snapshots: number;
    distinct_packages: number;
    distinct_contributors: number;
    avg_anomaly_score_7d: number | null;
    high_risk_events_7d: number;
}

interface RiskBreakdown {
    entity_type: string;
    window_days: number;
    breakdown: Record<string, number>;
}

interface Mover {
    entity_name: string;
    ecosystem: string | null;
    earliest_score: number;
    latest_score: number;
    delta: number;
    abs_delta: number;
    snapshots: number;
}

interface TimelinePoint {
    recorded_at: string;
    anomaly_score: number | null;
    trust_score: number | null;
    risk_level: string;
    triggered_rules: string[] | null;
}

/* ─── Colour helpers ──────────────────────────────────────────── */

const RISK_COLORS: Record<string, string> = {
    critical: '#d32f2f',
    high: '#ed6c02',
    medium: '#ffa726',
    low: '#66bb6a',
};

const PIE_COLORS = ['#66bb6a', '#ffa726', '#ed6c02', '#d32f2f'];

const riskChipColor = (level: string) => {
    switch (level) {
        case 'critical': return 'error' as const;
        case 'high': return 'warning' as const;
        case 'medium': return 'info' as const;
        default: return 'success' as const;
    }
};

/* ─── Custom chart tooltip ────────────────────────────────────── */

const CustomTooltip = ({ active, payload, label }: any) => {
    if (!active || !payload?.length) return null;
    return (
        <Box sx={{
            bgcolor: 'background.paper', p: 1.5, borderRadius: 1,
            border: '1px solid', borderColor: 'divider', boxShadow: 3,
        }}>
            <Typography variant="caption" color="text.secondary" display="block">
                {label}
            </Typography>
            {payload.map((entry: any, i: number) => (
                <Typography key={i} variant="body2" fontWeight="bold" sx={{ color: entry.color }}>
                    {entry.name}: {entry.value?.toFixed(2) ?? '—'}
                </Typography>
            ))}
        </Box>
    );
};

/* ═══════════════════════════════════════════════════════════════
   Trends Page Component
   ═══════════════════════════════════════════════════════════════ */

export const Trends: React.FC = () => {
    const theme = useTheme();

    /* ── Global data ────────────────────────────────────────────── */
    const [loading, setLoading] = useState(true);
    const [stats, setStats] = useState<TrendStats | null>(null);
    const [riskBreakdown, setRiskBreakdown] = useState<RiskBreakdown | null>(null);
    const [movers, setMovers] = useState<Mover[]>([]);

    /* ── Timeline lookup ────────────────────────────────────────── */
    const [entityType, setEntityType] = useState<'package' | 'contributor'>('package');
    const [entityName, setEntityName] = useState('');
    const [timelineDays, setTimelineDays] = useState(90);
    const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
    const [timelineLoading, setTimelineLoading] = useState(false);
    const [timelineError, setTimelineError] = useState('');

    /* ── Time range filter ──────────────────────────────────────── */
    const [timeRange, setTimeRange] = useState<'7d'|'30d'|'90d'|'all'>('30d');

    /* ── Fetch dashboard data ───────────────────────────────────── */
    const loadDashboard = useCallback(async () => {
        setLoading(true);
        try {
            const [statsRes, breakdownRes, moversRes] = await Promise.allSettled([
                api.trends.getStats(timeRange),
                api.trends.getRiskBreakdown('package', 7),
                api.trends.getTopMovers('package', 30, 20),
            ]);

            if (statsRes.status === 'fulfilled') setStats(statsRes.value);
            if (breakdownRes.status === 'fulfilled') setRiskBreakdown(breakdownRes.value);
            if (moversRes.status === 'fulfilled') setMovers(moversRes.value.movers ?? []);
        } catch (err) {
            console.error('Failed to load trend dashboard', err);
        } finally {
            setLoading(false);
        }
    }, [timeRange]);

    useEffect(() => { loadDashboard(); }, [loadDashboard]);

    /* ── Fetch timeline ─────────────────────────────────────────── */
    const handleTimelineLookup = async () => {
        if (!entityName.trim()) return;
        setTimelineLoading(true);
        setTimelineError('');
        setTimeline([]);
        try {
            const res = await api.trends.getTimeline(
                entityType, entityName.trim(), timelineDays,
            );
            setTimeline(res.timeline ?? []);
        } catch (err: any) {
            const msg = err?.response?.data?.detail || 'No trend data found.';
            setTimelineError(msg);
        } finally {
            setTimelineLoading(false);
        }
    };

    /* ── Chart data transforms ──────────────────────────────────── */
    const pieData = riskBreakdown
        ? ['low', 'medium', 'high', 'critical']
            .map((level) => ({
                name: level.charAt(0).toUpperCase() + level.slice(1),
                value: riskBreakdown.breakdown[level] ?? 0,
            }))
            .filter((d) => d.value > 0)
        : [];

    const timelineChartData = timeline.map((pt) => ({
        date: new Date(pt.recorded_at).toLocaleDateString(undefined, {
            month: 'short', day: 'numeric',
        }),
        anomaly: pt.anomaly_score,
        trust: pt.trust_score,
    }));

    /* ── Loading state ──────────────────────────────────────────── */
    if (loading) {
        return (
            <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
                <CircularProgress />
            </Box>
        );
    }

    return (
        <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>

            {/* ─── Header ─────────────────────────────────────────────── */}
            <Box mb={4} display="flex" alignItems="center" justifyContent="space-between">
                <Box display="flex" alignItems="center" gap={2}>
                    <ShowChart color="primary" sx={{ fontSize: 40 }} />
                    <Box>
                        <Typography variant="h4" fontWeight="bold" color="primary.main">
                            Trend Analysis
                        </Typography>
                        <Typography variant="subtitle1" color="text.secondary">
                            Track anomaly score evolution and risk posture over time.
                        </Typography>
                    </Box>
                </Box>
                <Box display="flex" alignItems="center" gap={2}>
                    <ToggleButtonGroup
                        value={timeRange}
                        exclusive
                        onChange={(e, newVal) => { if (newVal) setTimeRange(newVal); }}
                        size="small"
                        color="primary"
                    >
                        <ToggleButton value="7d" sx={{ fontWeight: 'bold' }}>7d</ToggleButton>
                        <ToggleButton value="30d" sx={{ fontWeight: 'bold' }}>30d</ToggleButton>
                        <ToggleButton value="90d" sx={{ fontWeight: 'bold' }}>90d</ToggleButton>
                        <ToggleButton value="all" sx={{ fontWeight: 'bold' }}>All</ToggleButton>
                    </ToggleButtonGroup>
                    <Button
                        variant="outlined"
                        startIcon={<Refresh />}
                        onClick={loadDashboard}
                    >
                        Refresh
                    </Button>
                </Box>
            </Box>

            {/* ─── Stats Cards ────────────────────────────────────────── */}
            <Grid container spacing={3} sx={{ mb: 4 }}>
                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <GlassCard
                        title="Total Snapshots"
                        value={stats?.total_snapshots ?? 0}
                        icon={<BarChartIcon />}
                        color={theme.palette.primary.main}
                    />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <GlassCard
                        title="Tracked Packages"
                        value={stats?.distinct_packages ?? 0}
                        icon={<Assessment />}
                        color={theme.palette.info.main}
                    />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <GlassCard
                        title="7-Day Avg Score"
                        value={stats?.avg_anomaly_score_7d?.toFixed(1) ?? '—'}
                        icon={<TimelineIcon />}
                        color={theme.palette.warning.main}
                    />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <GlassCard
                        title="High-Risk (7d)"
                        value={stats?.high_risk_events_7d ?? 0}
                        icon={<Shield />}
                        color={theme.palette.error.main}
                    />
                </Grid>
            </Grid>

            {/* ─── Risk Breakdown + Top Movers ────────────────────────── */}
            <Grid container spacing={3} sx={{ mb: 4 }}>

                {/* Donut Chart */}
                <Grid size={{ xs: 12, md: 4 }}>
                    <Paper sx={{
                        p: 3, borderRadius: 2, height: 420, display: 'flex',
                        flexDirection: 'column', boxShadow: 3,
                    }}>
                        <Box display="flex" alignItems="center" gap={1} mb={2}>
                            <PieChartIcon color="primary" />
                            <Typography variant="h6" fontWeight="bold">
                                Risk Distribution
                            </Typography>
                        </Box>
                        {pieData.length === 0 ? (
                            <Box flex={1} display="flex" alignItems="center" justifyContent="center">
                                <Typography color="text.secondary">
                                    No risk data yet.
                                </Typography>
                            </Box>
                        ) : (
                            <ResponsiveContainer width="100%" height={320}>
                                <PieChart>
                                    <Pie
                                        data={pieData}
                                        cx="50%"
                                        cy="45%"
                                        innerRadius={65}
                                        outerRadius={110}
                                        paddingAngle={4}
                                        dataKey="value"
                                        label={({ name, percent }) =>
                                            `${name} ${(percent * 100).toFixed(0)}%`
                                        }
                                    >
                                        {pieData.map((_, idx) => (
                                            <Cell key={idx} fill={PIE_COLORS[idx % PIE_COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Legend verticalAlign="bottom" height={36} />
                                    <RechartsTooltip />
                                </PieChart>
                            </ResponsiveContainer>
                        )}
                    </Paper>
                </Grid>

                {/* Top Movers Table */}
                <Grid size={{ xs: 12, md: 8 }}>
                    <Paper sx={{
                        borderRadius: 2, height: 420, display: 'flex',
                        flexDirection: 'column', boxShadow: 3, overflow: 'hidden',
                    }}>
                        <Box display="flex" alignItems="center" gap={1} p={3} pb={1}>
                            <TrendingUp color="primary" />
                            <Typography variant="h6" fontWeight="bold">
                                Top Movers (30 days)
                            </Typography>
                        </Box>
                        {movers.length === 0 ? (
                            <Box flex={1} display="flex" alignItems="center" justifyContent="center">
                                <Typography color="text.secondary">
                                    No movement data available yet.
                                </Typography>
                            </Box>
                        ) : (
                            <TableContainer sx={{ flex: 1 }}>
                                <Table size="small" stickyHeader>
                                    <TableHead>
                                        <TableRow>
                                            <TableCell sx={{ fontWeight: 'bold' }}>Package</TableCell>
                                            <TableCell sx={{ fontWeight: 'bold' }} align="center">Ecosystem</TableCell>
                                            <TableCell sx={{ fontWeight: 'bold' }} align="center">From</TableCell>
                                            <TableCell sx={{ fontWeight: 'bold' }} align="center">To</TableCell>
                                            <TableCell sx={{ fontWeight: 'bold' }} align="center">Delta</TableCell>
                                            <TableCell sx={{ fontWeight: 'bold' }} align="center">Scans</TableCell>
                                        </TableRow>
                                    </TableHead>
                                    <TableBody>
                                        {movers.map((m, idx) => {
                                            const isUp = m.delta > 0;
                                            return (
                                                <TableRow key={idx} hover>
                                                    <TableCell>
                                                        <Typography variant="body2" fontWeight="bold">
                                                            {m.entity_name}
                                                        </Typography>
                                                    </TableCell>
                                                    <TableCell align="center">
                                                        <Chip
                                                            label={m.ecosystem || '—'}
                                                            size="small"
                                                            color="primary"
                                                            variant="outlined"
                                                        />
                                                    </TableCell>
                                                    <TableCell align="center">
                                                        <Typography variant="body2">
                                                            {m.earliest_score?.toFixed(1) ?? '—'}
                                                        </Typography>
                                                    </TableCell>
                                                    <TableCell align="center">
                                                        <Typography variant="body2" fontWeight="bold">
                                                            {m.latest_score?.toFixed(1) ?? '—'}
                                                        </Typography>
                                                    </TableCell>
                                                    <TableCell align="center">
                                                        <Box display="flex" alignItems="center" justifyContent="center" gap={0.5}>
                                                            {isUp ? (
                                                                <ArrowUpward sx={{ fontSize: 16, color: 'error.main' }} />
                                                            ) : (
                                                                <ArrowDownward sx={{ fontSize: 16, color: 'success.main' }} />
                                                            )}
                                                            <Typography
                                                                variant="body2"
                                                                fontWeight="bold"
                                                                sx={{ color: isUp ? 'error.main' : 'success.main' }}
                                                            >
                                                                {isUp ? '+' : ''}{m.delta?.toFixed(1) ?? '—'}
                                                            </Typography>
                                                        </Box>
                                                    </TableCell>
                                                    <TableCell align="center">
                                                        <Chip label={m.snapshots} size="small" variant="outlined" />
                                                    </TableCell>
                                                </TableRow>
                                            );
                                        })}
                                    </TableBody>
                                </Table>
                            </TableContainer>
                        )}
                    </Paper>
                </Grid>
            </Grid>

            {/* ─── Timeline Lookup ────────────────────────────────────── */}
            <Paper sx={{ p: 3, borderRadius: 2, boxShadow: 3 }}>
                <Box display="flex" alignItems="center" gap={1} mb={3}>
                    <TimelineIcon color="primary" />
                    <Typography variant="h6" fontWeight="bold">
                        Entity Timeline Lookup
                    </Typography>
                </Box>

                {/* Controls */}
                <Box display="flex" gap={2} flexWrap="wrap" mb={3}>
                    <FormControl size="small" sx={{ minWidth: 140 }}>
                        <InputLabel id="entity-type-label">Entity Type</InputLabel>
                        <Select
                            labelId="entity-type-label"
                            value={entityType}
                            label="Entity Type"
                            onChange={(e) => setEntityType(e.target.value as 'package' | 'contributor')}
                        >
                            <MenuItem value="package">Package</MenuItem>
                            <MenuItem value="contributor">Contributor</MenuItem>
                        </Select>
                    </FormControl>

                    <TextField
                        size="small"
                        label="Entity Name"
                        placeholder="e.g. requests"
                        value={entityName}
                        onChange={(e) => setEntityName(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleTimelineLookup()}
                        sx={{ minWidth: 220 }}
                    />

                    <FormControl size="small" sx={{ minWidth: 120 }}>
                        <InputLabel id="days-label">Window</InputLabel>
                        <Select
                            labelId="days-label"
                            value={timelineDays}
                            label="Window"
                            onChange={(e) => setTimelineDays(Number(e.target.value))}
                        >
                            <MenuItem value={7}>7 days</MenuItem>
                            <MenuItem value={30}>30 days</MenuItem>
                            <MenuItem value={90}>90 days</MenuItem>
                            <MenuItem value={180}>180 days</MenuItem>
                            <MenuItem value={365}>1 year</MenuItem>
                        </Select>
                    </FormControl>

                    <Button
                        variant="contained"
                        startIcon={<Search />}
                        onClick={handleTimelineLookup}
                        disabled={!entityName.trim() || timelineLoading}
                    >
                        Lookup
                    </Button>
                </Box>

                {/* Timeline loading / error / chart */}
                {timelineLoading && <LinearProgress sx={{ mb: 2, borderRadius: 1 }} />}

                {timelineError && (
                    <Alert severity="info" sx={{ mb: 2 }}>
                        {timelineError}
                    </Alert>
                )}

                {timeline.length > 0 && (
                    <Box>
                        {/* Chart */}
                        <Box sx={{ height: 320, mb: 3 }}>
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={timelineChartData}>
                                    <defs>
                                        <linearGradient id="anomalyGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor={theme.palette.error.main} stopOpacity={0.35} />
                                            <stop offset="95%" stopColor={theme.palette.error.main} stopOpacity={0} />
                                        </linearGradient>
                                        <linearGradient id="trustGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor={theme.palette.success.main} stopOpacity={0.35} />
                                            <stop offset="95%" stopColor={theme.palette.success.main} stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke={alpha(theme.palette.divider, 0.4)} />
                                    <XAxis dataKey="date" tick={{ fontSize: 11 }} />
                                    <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
                                    <RechartsTooltip content={<CustomTooltip />} />
                                    <Area
                                        type="monotone"
                                        dataKey="anomaly"
                                        name="Anomaly Score"
                                        stroke={theme.palette.error.main}
                                        fill="url(#anomalyGrad)"
                                        strokeWidth={2}
                                        dot={false}
                                        activeDot={{ r: 5 }}
                                    />
                                    <Area
                                        type="monotone"
                                        dataKey="trust"
                                        name="Trust Score"
                                        stroke={theme.palette.success.main}
                                        fill="url(#trustGrad)"
                                        strokeWidth={2}
                                        dot={false}
                                        activeDot={{ r: 5 }}
                                    />
                                </AreaChart>
                            </ResponsiveContainer>
                        </Box>

                        {/* Data points table */}
                        <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                            Raw Data Points ({timeline.length})
                        </Typography>
                        <TableContainer sx={{ maxHeight: 300 }}>
                            <Table size="small" stickyHeader>
                                <TableHead>
                                    <TableRow>
                                        <TableCell sx={{ fontWeight: 'bold' }}>Date</TableCell>
                                        <TableCell sx={{ fontWeight: 'bold' }} align="center">Anomaly</TableCell>
                                        <TableCell sx={{ fontWeight: 'bold' }} align="center">Trust</TableCell>
                                        <TableCell sx={{ fontWeight: 'bold' }} align="center">Risk Level</TableCell>
                                        <TableCell sx={{ fontWeight: 'bold' }}>Triggered Rules</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {timeline.map((pt, idx) => (
                                        <TableRow key={idx} hover>
                                            <TableCell>
                                                <Typography variant="body2" color="text.secondary">
                                                    {new Date(pt.recorded_at).toLocaleString(undefined, {
                                                        month: 'short', day: 'numeric',
                                                        hour: '2-digit', minute: '2-digit',
                                                    })}
                                                </Typography>
                                            </TableCell>
                                            <TableCell align="center">
                                                <Typography
                                                    variant="body2"
                                                    fontWeight="bold"
                                                    sx={{
                                                        color: (pt.anomaly_score ?? 0) >= 50
                                                            ? 'error.main' : 'text.primary',
                                                    }}
                                                >
                                                    {pt.anomaly_score?.toFixed(1) ?? '—'}
                                                </Typography>
                                            </TableCell>
                                            <TableCell align="center">
                                                <Typography variant="body2">
                                                    {pt.trust_score?.toFixed(1) ?? '—'}
                                                </Typography>
                                            </TableCell>
                                            <TableCell align="center">
                                                <Chip
                                                    label={pt.risk_level}
                                                    size="small"
                                                    color={riskChipColor(pt.risk_level)}
                                                    sx={{ fontWeight: 'bold', textTransform: 'capitalize' }}
                                                />
                                            </TableCell>
                                            <TableCell>
                                                <Box display="flex" gap={0.5} flexWrap="wrap">
                                                    {(pt.triggered_rules ?? []).map((rule, ri) => (
                                                        <Chip
                                                            key={ri}
                                                            label={rule}
                                                            size="small"
                                                            variant="outlined"
                                                            sx={{ fontSize: '0.7rem', height: 22 }}
                                                        />
                                                    ))}
                                                    {(!pt.triggered_rules || pt.triggered_rules.length === 0) && (
                                                        <Typography variant="caption" color="text.secondary">
                                                            none
                                                        </Typography>
                                                    )}
                                                </Box>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </TableContainer>
                    </Box>
                )}

                {/* Empty state */}
                {!timelineLoading && !timelineError && timeline.length === 0 && (
                    <Box textAlign="center" py={6}>
                        <ShowChart sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
                        <Typography color="text.secondary">
                            Search for a package or contributor to see its score timeline.
                        </Typography>
                    </Box>
                )}
            </Paper>
        </Container>
    );
};

/* ─── Reusable Glass Card ─────────────────────────────────────── */

interface GlassCardProps {
    title: string;
    value: string | number;
    icon: React.ReactNode;
    color: string;
}

const GlassCard: React.FC<GlassCardProps> = ({ title, value, icon, color }) => {
    const theme = useTheme();
    return (
        <Card sx={{
            height: '100%',
            borderRadius: 2,
            boxShadow: 3,
            position: 'relative',
            overflow: 'hidden',
            '&::before': {
                content: '""',
                position: 'absolute',
                top: 0, left: 0, right: 0,
                height: 4,
                background: `linear-gradient(90deg, ${color}, ${alpha(color, 0.4)})`,
            },
        }}>
            <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={2}>
                    <Typography variant="subtitle2" fontWeight="bold" color="text.secondary">
                        {title}
                    </Typography>
                    <Box sx={{
                        p: 0.8, borderRadius: 1.5,
                        bgcolor: alpha(color, 0.12),
                        color: color,
                        display: 'flex',
                    }}>
                        {icon}
                    </Box>
                </Box>
                <Typography variant="h3" fontWeight="bold" sx={{ color }}>
                    {value}
                </Typography>
            </CardContent>
        </Card>
    );
};

export default Trends;
