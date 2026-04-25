import React, { useEffect, useState } from 'react';
import {
    Container, Grid, Paper, Typography, Box, CircularProgress, Card, CardContent,
    Chip, List, ListItem, ListItemIcon, ListItemText
} from '@mui/material';
import { Security, History, Timeline, Assessment, Speed, AccountTree } from '@mui/icons-material';
import api from '../api/client';

export const Dashboard: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [stats, setStats] = useState({
        alerts: { total: 0, critical: 0, high: 0, recent: [] as any[] },
        ledger: { total: 0, flagged: 0 },
        anomaly: { trained: false, features: 0 },
        health: { status: 'unknown', postgres: 'down', neo4j: 'down', redis: 'down' },
        scans: { recent: [] as any[] },
    });

    useEffect(() => {
        const refreshDashboard = async () => {
            try {
                const [alertsRes, ledgerRes, anomalyRes, healthRes, historyRes] = await Promise.all([
                    api.alerts.getStats(),
                    api.ledger.getStats(),
                    api.anomaly.getStatus(),
                    api.health.check(),
                    api.dependencies.getHistory(),
                ]);

                setStats({
                    alerts: {
                        total: alertsRes.total_alerts || 0,
                        critical: alertsRes.by_severity?.critical || 0,
                        high: alertsRes.by_severity?.high || 0,
                        recent: alertsRes.recent_alerts || [],
                    },
                    ledger: {
                        total: ledgerRes.total_entries || 0,
                        flagged: ledgerRes.flagged_entries || 0,
                    },
                    anomaly: {
                        trained: anomalyRes.is_trained === true,
                        features: anomalyRes.feature_count || 15,
                    },
                    health: {
                        status: healthRes.status || 'unknown',
                        postgres: healthRes.services?.postgres || 'down',
                        neo4j: healthRes.services?.neo4j || 'down',
                        redis: healthRes.services?.redis || 'down',
                    },
                    scans: {
                        recent: historyRes.scans?.slice(0, 5) || [],
                    },
                });
            } catch (error) {
                console.error("Failed to load dashboard stats", error);
            } finally {
                setLoading(false);
            }
        };

        refreshDashboard();
        const interval = setInterval(refreshDashboard, 30000);
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
                <CircularProgress />
            </Box>
        );
    }

    return (
        <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
            <Typography variant="h4" fontWeight="bold" gutterBottom color="primary.main">
                Mission Control
            </Typography>
            <Typography variant="subtitle1" color="text.secondary" gutterBottom sx={{ mb: 4 }}>
                Real-time overview of your supply chain security posture.
            </Typography>

            <Grid container spacing={3}>
                {/* ─── Top Metrics Row ──────────────────────────────────────── */}
                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <StatCard
                        title={
                            <Box display="flex" alignItems="center" gap={1}>
                                Critical Alerts
                                {stats.alerts.critical > 0 && (
                                    <Box
                                        sx={{
                                            width: 8,
                                            height: 8,
                                            borderRadius: '50%',
                                            backgroundColor: 'error.main',
                                            animation: 'pulse 2s infinite',
                                            '@keyframes pulse': {
                                                '0%': { transform: 'scale(0.95)', boxShadow: '0 0 0 0 rgba(211, 47, 47, 0.7)' },
                                                '70%': { transform: 'scale(1)', boxShadow: '0 0 0 6px rgba(211, 47, 47, 0)' },
                                                '100%': { transform: 'scale(0.95)', boxShadow: '0 0 0 0 rgba(211, 47, 47, 0)' },
                                            }
                                        }}
                                    />
                                )}
                            </Box>
                        }
                        value={stats.alerts.critical.toString()}
                        icon={<Security color="error" fontSize="large" />}
                        subtitle={`${stats.alerts.high} High Severity`}
                        color="error.main"
                    />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <StatCard
                        title="Ledger Entries"
                        value={stats.ledger.total.toString()}
                        icon={<History color="info" fontSize="large" />}
                        subtitle={`${stats.ledger.flagged} Flagged Events`}
                    />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <StatCard
                        title="Anomaly Engine"
                        value={stats.anomaly.trained ? "Live" : "Training"}
                        icon={<Speed color={stats.anomaly.trained ? "success" : "warning"} fontSize="large" />}
                        subtitle={`${stats.anomaly.features} Feature Vectors`}
                        color={stats.anomaly.trained ? "success.main" : "warning.main"}
                    />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <StatCard
                        title="System Status"
                        value={stats.health.status === 'healthy' ? 'Healthy' : 'Degraded'}
                        icon={<Assessment color={stats.health.status === 'healthy' ? 'success' : 'error'} fontSize="large" />}
                        subtitle={`PG:${stats.health.postgres} | Neo4j:${stats.health.neo4j} | Redis:${stats.health.redis}`}
                        color={stats.health.status === 'healthy' ? 'success.main' : 'error.main'}
                    />
                </Grid>

                {/* ─── Main Content Area ────────────────────────────────────── */}
                <Grid size={{ xs: 12, md: 8 }}>
                    <Paper sx={{ p: 3, display: 'flex', flexDirection: 'column', height: 400, borderRadius: 2 }}>
                        <Typography variant="h6" color="primary" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Timeline /> Recent Activity
                        </Typography>
                        <Box sx={{ flexGrow: 1, overflowY: 'auto' }}>
                            {stats.scans.recent.length === 0 ? (
                                <Box display="flex" alignItems="center" justifyContent="center" height="100%">
                                    <Typography color="text.secondary">No scans yet. Run your first scan from the Dependency Scanner.</Typography>
                                </Box>
                            ) : (
                                <List disablePadding>
                                    {stats.scans.recent.map((scan: any, idx: number) => (
                                        <ListItem
                                            key={idx}
                                            sx={{
                                                borderBottom: '1px solid',
                                                borderColor: 'divider',
                                                py: 1.5,
                                            }}
                                            secondaryAction={
                                                scan.alerts_generated > 0 ? (
                                                    <Chip
                                                        label={`${scan.alerts_generated} alert${scan.alerts_generated > 1 ? 's' : ''}`}
                                                        size="small"
                                                        color="warning"
                                                    />
                                                ) : null
                                            }
                                        >
                                            <ListItemIcon sx={{ minWidth: 40 }}>
                                                <AccountTree color={scan.alerts_generated > 0 ? 'warning' : 'success'} />
                                            </ListItemIcon>
                                            <ListItemText
                                                primary={
                                                    <Typography variant="body2" fontWeight="bold">
                                                        {scan.project_name} — {scan.total_packages} packages
                                                    </Typography>
                                                }
                                                secondary={
                                                    <Box component="span" display="flex" alignItems="center" gap={1} mt={0.5}>
                                                        <Chip label={scan.ecosystem} size="small" color="primary" variant="outlined" sx={{ height: 20, fontSize: '0.7rem' }} component="span" />
                                                        <Typography variant="caption" component="span" color="text.secondary">
                                                            {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : '—'}
                                                        </Typography>
                                                    </Box>
                                                }
                                                secondaryTypographyProps={{ component: 'span' }}
                                            />
                                        </ListItem>
                                    ))}
                                </List>
                            )}
                        </Box>
                    </Paper>
                </Grid>

                {/* ─── Side Content ─────────────────────────────────────────── */}
                <Grid size={{ xs: 12, md: 4 }}>
                    <Paper sx={{ p: 3, display: 'flex', flexDirection: 'column', height: 400, borderRadius: 2 }}>
                        <Typography variant="h6" color="primary" gutterBottom>
                            Active Threats
                        </Typography>
                        <Box sx={{ flexGrow: 1, overflowY: 'auto', mt: 2 }}>
                            {stats.alerts.recent.length === 0 ? (
                                <Typography color="text.secondary" align="center" sx={{ mt: 4 }}>
                                    No active alerts. Good job!
                                </Typography>
                            ) : (
                                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                    {stats.alerts.recent.map((alert, idx) => (
                                        <Box key={idx} sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, p: 1.5, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                <Typography variant="subtitle2" noWrap sx={{ maxWidth: '70%', fontWeight: 'bold' }}>
                                                    {alert.title}
                                                </Typography>
                                                <Typography variant="caption" sx={{
                                                    px: 1, py: 0.5, borderRadius: 1, fontWeight: 'bold', textTransform: 'uppercase', fontSize: '0.65rem',
                                                    bgcolor: alert.severity === 'critical' ? 'error.dark' : alert.severity === 'high' ? 'error.main' : alert.severity === 'medium' ? 'warning.main' : 'info.main',
                                                    color: 'white'
                                                }}>
                                                    {alert.severity}
                                                </Typography>
                                            </Box>
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                <Typography variant="body2" color="text.secondary">
                                                    {alert.package_name}
                                                </Typography>
                                                <Typography variant="caption" color="text.secondary">
                                                    {new Date(alert.created_at).toLocaleDateString()}
                                                </Typography>
                                            </Box>
                                        </Box>
                                    ))}
                                </Box>
                            )}
                        </Box>
                    </Paper>
                </Grid>
            </Grid>
        </Container>
    );
};

// ─── Reusable Components ─────────────────────────────────────────────

interface StatCardProps {
    title: React.ReactNode;
    value: string | number;
    subtitle: string;
    icon: React.ReactNode;
    color?: string;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, subtitle, icon, color }) => (
    <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column', borderRadius: 2, boxShadow: 2 }}>
        <CardContent sx={{ flexGrow: 1 }}>
            <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={2}>
                <Typography color="text.secondary" gutterBottom variant="subtitle2" fontWeight="bold">
                    {title}
                </Typography>
                {icon}
            </Box>
            <Typography component="div" variant="h3" fontWeight="heavy" color={color || 'text.primary'}>
                {value}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                {subtitle}
            </Typography>
        </CardContent>
    </Card>
);

export default Dashboard;
