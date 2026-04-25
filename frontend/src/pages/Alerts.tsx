import React, { useEffect, useState } from 'react';
import {
    Container, Typography, Paper, Box, CircularProgress,
    Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
    Chip, Button, FormControl, InputLabel, Select, MenuItem,
    Dialog, DialogTitle, DialogContent, DialogActions, Grid, IconButton, Tooltip, Checkbox
} from '@mui/material';
import { Warning, CheckCircle, Visibility, Build, DeleteOutline, AutoAwesome, Refresh } from '@mui/icons-material';
import api from '../api/client';

export const Alerts: React.FC = () => {
    const [alerts, setAlerts] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [total, setTotal] = useState(0);

    // Filters
    const [statusFilter, setStatusFilter] = useState<string>('open');
    const [severityFilter, setSeverityFilter] = useState<string>('all');

    // Selection
    const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());

    // Detail Modal
    const [selectedAlert, setSelectedAlert] = useState<any | null>(null);

    // AI Explanation panel
    const [explanation, setExplanation] = useState<string>('');
    const [explanationLoading, setExplanationLoading] = useState(false);
    const [explanationFallback, setExplanationFallback] = useState(false);

    const fetchExplanation = async (alertId: number) => {
        setExplanationLoading(true);
        setExplanationFallback(false);
        setExplanation('');
        try {
            const res = await api.ai.explain(alertId);
            setExplanation(res.explanation || '');
            setExplanationFallback(!!res.fallback);
        } catch {
            setExplanation('AI explanation temporarily unavailable. Please try again later.');
            setExplanationFallback(true);
        } finally {
            setExplanationLoading(false);
        }
    };

    const loadAlerts = async () => {
        setLoading(true);
        try {
            const params: any = { limit: 100 };
            if (statusFilter !== 'all') params.status = statusFilter;
            if (severityFilter !== 'all') params.severity = severityFilter;

            const res = await api.alerts.list(params);
            setAlerts(res.alerts || []);
            setTotal(res.total || 0);
            setSelectedIds(new Set()); // clear selection on reload
        } catch (err) {
            console.error("Failed to load alerts:", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadAlerts();
    }, [statusFilter, severityFilter]);

    const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.checked) {
            setSelectedIds(new Set(alerts.map(a => a.id)));
        } else {
            setSelectedIds(new Set());
        }
    };

    const handleSelectOne = (id: number) => {
        const newSet = new Set(selectedIds);
        if (newSet.has(id)) {
            newSet.delete(id);
        } else {
            newSet.add(id);
        }
        setSelectedIds(newSet);
    };

    const handleBulkStatusUpdate = async (newStatus: string) => {
        if (selectedIds.size === 0) return;
        try {
            await api.alerts.bulkUpdateStatus(Array.from(selectedIds), newStatus);
            await loadAlerts();
        } catch (err) {
            console.error("Bulk update failed", err);
        }
    };

    const getSeverityColor = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'error';
            case 'high': return 'error';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'default';
        }
    };

    const getStatusColor = (status: string) => {
        switch (status.toLowerCase()) {
            case 'open': return 'error';
            case 'investigating': return 'warning';
            case 'resolved': return 'success';
            case 'dismissed': return 'default';
            default: return 'default';
        }
    };

    return (
        <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
            <Box mb={4} display="flex" alignItems="center" gap={2}>
                <Warning color="error" sx={{ fontSize: 40 }} />
                <Box>
                    <Typography variant="h4" fontWeight="bold" color="text.primary">
                        Alert Management
                    </Typography>
                    <Typography variant="subtitle1" color="text.secondary">
                        Triage, investigate, and resolve security threats.
                    </Typography>
                </Box>
            </Box>

            <Paper sx={{ p: 3, mb: 4, borderRadius: 2 }}>
                <Grid container spacing={3} alignItems="center">
                    <Grid item xs={12} sm={4}>
                        <FormControl fullWidth size="small">
                            <InputLabel>Status</InputLabel>
                            <Select
                                value={statusFilter}
                                label="Status"
                                onChange={(e) => setStatusFilter(e.target.value)}
                            >
                                <MenuItem value="all">All Statuses</MenuItem>
                                <MenuItem value="open">Open</MenuItem>
                                <MenuItem value="investigating">Investigating</MenuItem>
                                <MenuItem value="resolved">Resolved</MenuItem>
                                <MenuItem value="dismissed">Dismissed</MenuItem>
                            </Select>
                        </FormControl>
                    </Grid>
                    <Grid item xs={12} sm={4}>
                        <FormControl fullWidth size="small">
                            <InputLabel>Severity</InputLabel>
                            <Select
                                value={severityFilter}
                                label="Severity"
                                onChange={(e) => setSeverityFilter(e.target.value)}
                            >
                                <MenuItem value="all">All Severities</MenuItem>
                                <MenuItem value="critical">Critical</MenuItem>
                                <MenuItem value="high">High</MenuItem>
                                <MenuItem value="medium">Medium</MenuItem>
                                <MenuItem value="low">Low</MenuItem>
                            </Select>
                        </FormControl>
                    </Grid>
                    <Grid item xs={12} sm={4} display="flex" justifyContent="flex-end" gap={1}>
                        <Button
                            variant="outlined"
                            color="success"
                            disabled={selectedIds.size === 0}
                            startIcon={<CheckCircle />}
                            onClick={() => handleBulkStatusUpdate('resolved')}
                        >
                            Resolve Selected
                        </Button>
                        <Button
                            variant="outlined"
                            color="inherit"
                            disabled={selectedIds.size === 0}
                            startIcon={<DeleteOutline />}
                            onClick={() => handleBulkStatusUpdate('dismissed')}
                        >
                            Dismiss Selected
                        </Button>
                    </Grid>
                </Grid>
            </Paper>

            <TableContainer component={Paper} sx={{ borderRadius: 2, boxShadow: 2 }}>
                <Table sx={{ minWidth: 650 }}>
                    <TableHead sx={{ bgcolor: 'background.default' }}>
                        <TableRow>
                            <TableCell padding="checkbox">
                                <Checkbox
                                    indeterminate={selectedIds.size > 0 && selectedIds.size < alerts.length}
                                    checked={alerts.length > 0 && selectedIds.size === alerts.length}
                                    onChange={handleSelectAll}
                                />
                            </TableCell>
                            <TableCell><b>Target</b></TableCell>
                            <TableCell><b>Title</b></TableCell>
                            <TableCell><b>Severity</b></TableCell>
                            <TableCell><b>Status</b></TableCell>
                            <TableCell><b>Created</b></TableCell>
                            <TableCell align="right"><b>Actions</b></TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {loading ? (
                            <TableRow>
                                <TableCell colSpan={7} align="center" sx={{ py: 6 }}>
                                    <CircularProgress />
                                </TableCell>
                            </TableRow>
                        ) : alerts.length === 0 ? (
                            <TableRow>
                                <TableCell colSpan={7} align="center" sx={{ py: 6 }}>
                                    <Typography color="text.secondary">No alerts found matching your filters.</Typography>
                                </TableCell>
                            </TableRow>
                        ) : (
                            alerts.map((alert) => (
                                <TableRow key={alert.id} hover selected={selectedIds.has(alert.id)}>
                                    <TableCell padding="checkbox">
                                        <Checkbox
                                            checked={selectedIds.has(alert.id)}
                                            onChange={() => handleSelectOne(alert.id)}
                                        />
                                    </TableCell>
                                    <TableCell>
                                        <Typography variant="body2" fontWeight="bold">
                                            {alert.package_name}
                                        </Typography>
                                        {alert.contributor_username && (
                                            <Typography variant="caption" color="text.secondary">
                                                User: {alert.contributor_username}
                                            </Typography>
                                        )}
                                    </TableCell>
                                    <TableCell sx={{ maxWidth: 300 }}>
                                        <Typography variant="body2" noWrap>
                                            {alert.title}
                                        </Typography>
                                    </TableCell>
                                    <TableCell>
                                        <Chip
                                            label={alert.severity.toUpperCase()}
                                            size="small"
                                            color={getSeverityColor(alert.severity) as any}
                                            sx={{ fontWeight: 'bold' }}
                                        />
                                    </TableCell>
                                    <TableCell>
                                        <Chip
                                            label={alert.status.toUpperCase()}
                                            size="small"
                                            variant="outlined"
                                            color={getStatusColor(alert.status) as any}
                                        />
                                    </TableCell>
                                    <TableCell>
                                        <Typography variant="body2">
                                            {new Date(alert.created_at).toLocaleDateString()}
                                        </Typography>
                                    </TableCell>
                                    <TableCell align="right">
                                        <Tooltip title="View Details">
                                            <IconButton color="primary" onClick={() => setSelectedAlert(alert)}>
                                                <Visibility />
                                            </IconButton>
                                        </Tooltip>
                                    </TableCell>
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* ─── Detail Modal ────────────────────────────────────────── */}
            <Dialog
                open={!!selectedAlert}
                onClose={() => { setSelectedAlert(null); setExplanation(''); }}
                maxWidth="md"
                fullWidth
                TransitionProps={{
                    onEntered: () => { if (selectedAlert) fetchExplanation(selectedAlert.id); }
                }}
            >
                {selectedAlert && (
                    <>
                        <DialogTitle sx={{ borderBottom: 1, borderColor: 'divider', pb: 2 }}>
                            <Box display="flex" justifyContent="space-between" alignItems="center">
                                <Typography variant="h6" fontWeight="bold">
                                    {selectedAlert.title}
                                </Typography>
                                <Chip
                                    label={selectedAlert.severity.toUpperCase()}
                                    color={getSeverityColor(selectedAlert.severity) as any}
                                    size="small"
                                />
                            </Box>
                        </DialogTitle>
                        <DialogContent dividers>
                            <Grid container spacing={3}>
                                <Grid item xs={12}>
                                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                        Description
                                    </Typography>
                                    <Typography variant="body1" paragraph>
                                        {selectedAlert.description}
                                    </Typography>
                                </Grid>

                                <Grid item xs={6}>
                                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                        Package
                                    </Typography>
                                    <Typography variant="body1">
                                        {selectedAlert.package_name} {selectedAlert.package_version && `v${selectedAlert.package_version}`}
                                    </Typography>
                                </Grid>

                                <Grid item xs={6}>
                                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                        Status
                                    </Typography>
                                    <Chip
                                        label={selectedAlert.status.toUpperCase()}
                                        color={getStatusColor(selectedAlert.status) as any}
                                        size="small"
                                    />
                                </Grid>

                                <Grid item xs={12}>
                                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                        Evidence (Raw JSON)
                                    </Typography>
                                    <Box
                                        component="pre"
                                        sx={{
                                            p: 2,
                                            bgcolor: '#1e1e1e',
                                            color: '#d4d4d4',
                                            borderRadius: 1,
                                            overflowX: 'auto',
                                            fontSize: '0.85rem'
                                        }}
                                    >
                                        {JSON.stringify(selectedAlert.evidence, null, 2)}
                                    </Box>
                                </Grid>

                                {/* ─── AI Explanation Panel ─────────── */}
                                <Grid item xs={12}>
                                    <Box
                                        sx={{
                                            p: 2,
                                            borderRadius: 2,
                                            border: '1px solid',
                                            borderColor: 'divider',
                                            bgcolor: 'background.default',
                                        }}
                                    >
                                        <Box display="flex" alignItems="center" justifyContent="space-between" mb={1}>
                                            <Box display="flex" alignItems="center" gap={1}>
                                                <AutoAwesome fontSize="small" color="primary" />
                                                <Typography variant="subtitle2" color="text.secondary" fontWeight="bold">
                                                    AI Explanation
                                                </Typography>
                                            </Box>
                                            {explanationFallback && (
                                                <Button
                                                    size="small"
                                                    startIcon={<Refresh />}
                                                    onClick={() => fetchExplanation(selectedAlert.id)}
                                                    variant="outlined"
                                                >
                                                    Retry
                                                </Button>
                                            )}
                                        </Box>
                                        {explanationLoading ? (
                                            <Box display="flex" alignItems="center" gap={1}>
                                                <CircularProgress size={16} />
                                                <Typography variant="body2" color="text.secondary">
                                                    Generating explanation…
                                                </Typography>
                                            </Box>
                                        ) : (
                                            <Typography
                                                variant="body2"
                                                color={explanationFallback ? 'text.disabled' : 'text.primary'}
                                                sx={{ whiteSpace: 'pre-wrap' }}
                                            >
                                                {explanation || '—'}
                                            </Typography>
                                        )}
                                    </Box>
                                </Grid>
                            </Grid>
                        </DialogContent>
                        <DialogActions sx={{ p: 2 }}>
                            <Button onClick={() => setSelectedAlert(null)} color="inherit">
                                Close
                            </Button>
                            {selectedAlert.status !== 'investigating' && (
                                <Button
                                    variant="contained"
                                    color="warning"
                                    onClick={async () => {
                                        await api.alerts.updateStatus(selectedAlert.id, 'investigating');
                                        await loadAlerts();
                                        setSelectedAlert({ ...selectedAlert, status: 'investigating' });
                                    }}
                                >
                                    Mark Investigating
                                </Button>
                            )}
                            {selectedAlert.status !== 'resolved' && (
                                <Button
                                    variant="contained"
                                    color="success"
                                    onClick={async () => {
                                        await api.alerts.updateStatus(selectedAlert.id, 'resolved');
                                        await loadAlerts();
                                        setSelectedAlert(null);
                                    }}
                                >
                                    Resolve Alert
                                </Button>
                            )}
                        </DialogActions>
                    </>
                )}
            </Dialog>
        </Container>
    );
};

export default Alerts;
