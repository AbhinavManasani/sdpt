import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Container, Typography, Paper, Box, Button, Chip, Divider,
    CircularProgress, Dialog, DialogTitle, DialogContent, DialogActions,
    TableContainer, Table, TableHead, TableRow, TableCell, TableBody
} from '@mui/material';
import { ManageSearch, Refresh, Visibility, CheckCircle, BugReport, History } from '@mui/icons-material';
import api from '../api/client';

export const ScanHistory: React.FC = () => {
    const navigate = useNavigate();
    const [scans, setScans] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [detailOpen, setDetailOpen] = useState(false);
    const [detail, setDetail] = useState<any>(null);
    const [detailLoading, setDetailLoading] = useState(false);
    const [cveData, setCveData] = useState<any>(null);

    const loadHistory = async () => {
        setLoading(true);
        try {
            const res = await api.dependencies.getHistory();
            setScans(res.scans || []);
        } catch (err) {
            console.error('Failed to load scan history', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadHistory();
    }, []);

    const handleViewDetail = async (scanId: number) => {
        setDetailOpen(true);
        setDetailLoading(true);
        setDetail(null);
        setCveData(null);
        try {
            const [res, cveRes] = await Promise.all([
                api.dependencies.getScanDetail(scanId),
                api.cve.getByScan(scanId).catch(() => null),
            ]);
            setDetail(res);
            setCveData(cveRes);
        } catch (err) {
            console.error('Failed to load scan detail', err);
        } finally {
            setDetailLoading(false);
        }
    };

    const formatDate = (iso: string | null) => {
        if (!iso) return '—';
        const d = new Date(iso);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    };

    return (
        <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
            <Box mb={4} display="flex" alignItems="center" justifyContent="space-between">
                <Box display="flex" alignItems="center" gap={2}>
                    <ManageSearch color="primary" sx={{ fontSize: 40 }} />
                    <Box>
                        <Typography variant="h4" fontWeight="bold" color="primary.main">
                            Scan History
                        </Typography>
                        <Typography variant="subtitle1" color="text.secondary">
                            Browse and inspect previous dependency scans.
                        </Typography>
                    </Box>
                </Box>
                <Button
                    variant="outlined"
                    startIcon={<Refresh />}
                    onClick={loadHistory}
                    disabled={loading}
                >
                    Refresh
                </Button>
            </Box>

            <Paper sx={{ borderRadius: 2, boxShadow: 3, overflow: 'hidden' }}>
                {loading ? (
                    <Box display="flex" justifyContent="center" alignItems="center" p={8}>
                        <CircularProgress />
                    </Box>
                ) : scans.length === 0 ? (
                    <Box p={8} textAlign="center">
                        <ManageSearch sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
                        <Typography color="text.secondary">No scans yet. Run a scan from the Dependency Scanner.</Typography>
                    </Box>
                ) : (
                    <TableContainer>
                        <Table>
                            <TableHead>
                                <TableRow sx={{ bgcolor: 'primary.dark' }}>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>ID</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Project Name</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Ecosystem</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>File Type</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }} align="center">Total Packages</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }} align="center">Alerts</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Scanned At</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }} align="center">Actions</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {scans.map((scan) => (
                                    <TableRow key={scan.id} hover>
                                        <TableCell>{scan.id}</TableCell>
                                        <TableCell>
                                            <Typography variant="body2" fontWeight="bold">
                                                {scan.project_name}
                                            </Typography>
                                        </TableCell>
                                        <TableCell>
                                            <Chip label={scan.ecosystem} size="small" color="primary" />
                                        </TableCell>
                                        <TableCell>
                                            <Typography variant="body2" color="text.secondary">
                                                {scan.file_type}
                                            </Typography>
                                        </TableCell>
                                        <TableCell align="center">{scan.total_packages}</TableCell>
                                        <TableCell align="center">
                                            <Chip
                                                label={scan.alerts_generated}
                                                size="small"
                                                color={scan.alerts_generated > 0 ? 'warning' : 'default'}
                                                variant={scan.alerts_generated > 0 ? 'filled' : 'outlined'}
                                            />
                                        </TableCell>
                                        <TableCell>
                                            <Typography variant="body2" color="text.secondary">
                                                {formatDate(scan.created_at)}
                                            </Typography>
                                        </TableCell>
                                        <TableCell align="center">
                                            <Button
                                                size="small"
                                                variant="outlined"
                                                startIcon={<Visibility />}
                                                onClick={() => handleViewDetail(scan.id)}
                                            >
                                                View Details
                                            </Button>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </TableContainer>
                )}
            </Paper>

            {/* ─── Detail Dialog ──────────────────────────────────────── */}
            <Dialog open={detailOpen} onClose={() => setDetailOpen(false)} maxWidth="lg" fullWidth>
                <DialogTitle sx={{ fontWeight: 'bold' }}>
                    Scan Detail {detail ? `— ${detail.project_name}` : ''}
                </DialogTitle>
                <DialogContent dividers>
                    {detailLoading ? (
                        <Box display="flex" justifyContent="center" p={4}>
                            <CircularProgress />
                        </Box>
                    ) : detail ? (
                        <Box>
                            {/* Summary */}
                            <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                                Scan Summary
                            </Typography>
                            <Box display="flex" gap={2} flexWrap="wrap" mb={3}>
                                <Chip label={`Duration: ${detail.scan_duration_seconds?.toFixed(2) || '0.00'}s`} size="small" variant="outlined" />
                                <Chip label={`Total Packages: ${detail.total_packages}`} size="small" variant="outlined" />
                                <Chip label={`Direct: ${detail.direct_dependencies}`} size="small" color="primary" />
                                <Chip label={`Transitive: ${detail.transitive_dependencies}`} size="small" color="info" />
                                <Chip label={detail.ecosystem} size="small" color="primary" />
                                <Chip label={detail.status} size="small" color={detail.status === 'completed' ? 'success' : 'warning'} />
                            </Box>

                            {/* Anomaly Summary */}
                            <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                                Anomaly Summary
                            </Typography>
                            <Box display="flex" gap={2} flexWrap="wrap" mb={3}>
                                <Chip label={`Packages Scored: ${detail.packages_scored}`} size="small" variant="outlined" />
                                <Chip
                                    label={`High Risk: ${detail.high_risk}`}
                                    size="small"
                                    color={detail.high_risk > 0 ? 'error' : 'default'}
                                    variant={detail.high_risk > 0 ? 'filled' : 'outlined'}
                                />
                                <Chip
                                    label={`Critical Risk: ${detail.critical_risk}`}
                                    size="small"
                                    color={detail.critical_risk > 0 ? 'error' : 'default'}
                                    variant={detail.critical_risk > 0 ? 'filled' : 'outlined'}
                                />
                                <Chip
                                    label={`Alerts Generated: ${detail.alerts_generated}`}
                                    size="small"
                                    color={detail.alerts_generated > 0 ? 'warning' : 'default'}
                                    variant={detail.alerts_generated > 0 ? 'filled' : 'outlined'}
                                />
                            </Box>

                            <Divider sx={{ mb: 2 }} />

                            {/* Packages Table */}
                            <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                                Packages ({detail.packages?.length || 0})
                            </Typography>
                            <TableContainer sx={{ maxHeight: 400 }}>
                                <Table size="small" stickyHeader>
                                    <TableHead>
                                        <TableRow>
                                            <TableCell sx={{ fontWeight: 'bold' }}>Package</TableCell>
                                            <TableCell sx={{ fontWeight: 'bold' }}>Type</TableCell>
                                            <TableCell sx={{ fontWeight: 'bold' }}>License</TableCell>
                                            <TableCell sx={{ fontWeight: 'bold' }}>Author</TableCell>
                                            <TableCell sx={{ fontWeight: 'bold' }} align="center">Anomaly</TableCell>
                                        </TableRow>
                                    </TableHead>
                                    <TableBody>
                                        {(detail.packages || []).map((pkg: any, idx: number) => (
                                            <TableRow key={idx} hover>
                                                <TableCell>
                                                    <Typography variant="body2" fontWeight="bold">{pkg.name}</Typography>
                                                    <Typography variant="caption" color="text.secondary">{pkg.version || 'latest'}</Typography>
                                                </TableCell>
                                                <TableCell>
                                                    <Chip
                                                        label={pkg.is_direct ? 'Direct' : 'Transitive'}
                                                        size="small"
                                                        color={pkg.is_direct ? 'primary' : 'default'}
                                                        variant={pkg.is_direct ? 'filled' : 'outlined'}
                                                    />
                                                </TableCell>
                                                <TableCell>
                                                    <Typography variant="body2" color="text.secondary">{pkg.license || '—'}</Typography>
                                                </TableCell>
                                                <TableCell>
                                                    <Typography variant="body2" color="text.secondary">{pkg.author || '—'}</Typography>
                                                </TableCell>
                                                <TableCell align="center">
                                                    <CheckCircle color="success" fontSize="small" />
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            </TableContainer>

                            {/* CVE Findings */}
                            {cveData && cveData.total_cves > 0 && (
                                <Box mt={3}>
                                    <Divider sx={{ mb: 2 }} />
                                    <Box display="flex" alignItems="center" gap={1} mb={1}>
                                        <BugReport color="error" />
                                        <Typography variant="subtitle2" fontWeight="bold">
                                            CVE Findings ({cveData.total_cves})
                                        </Typography>
                                    </Box>
                                    <Box display="flex" gap={1} flexWrap="wrap" mb={2}>
                                        {cveData.by_severity?.critical > 0 && (
                                            <Chip label={`Critical: ${cveData.by_severity.critical}`} size="small" color="error" />
                                        )}
                                        {cveData.by_severity?.high > 0 && (
                                            <Chip label={`High: ${cveData.by_severity.high}`} size="small" sx={{ bgcolor: '#ed6c02', color: 'white' }} />
                                        )}
                                        {cveData.by_severity?.medium > 0 && (
                                            <Chip label={`Medium: ${cveData.by_severity.medium}`} size="small" color="warning" />
                                        )}
                                        {cveData.by_severity?.low > 0 && (
                                            <Chip label={`Low: ${cveData.by_severity.low}`} size="small" variant="outlined" />
                                        )}
                                    </Box>
                                    <TableContainer sx={{ maxHeight: 300 }}>
                                        <Table size="small" stickyHeader>
                                            <TableHead>
                                                <TableRow>
                                                    <TableCell sx={{ fontWeight: 'bold' }}>CVE ID</TableCell>
                                                    <TableCell sx={{ fontWeight: 'bold' }}>Package</TableCell>
                                                    <TableCell sx={{ fontWeight: 'bold' }} align="center">CVSS</TableCell>
                                                    <TableCell sx={{ fontWeight: 'bold' }}>Severity</TableCell>
                                                    <TableCell sx={{ fontWeight: 'bold' }}>Description</TableCell>
                                                </TableRow>
                                            </TableHead>
                                            <TableBody>
                                                {(cveData.findings || []).slice(0, 5).map((cve: any, idx: number) => (
                                                    <TableRow key={idx} hover>
                                                        <TableCell>
                                                            <Chip label={cve.cve_id} size="small" variant="outlined" color="error" />
                                                        </TableCell>
                                                        <TableCell>
                                                            <Typography variant="body2" fontWeight="bold">{cve.package_name}</Typography>
                                                            <Typography variant="caption" color="text.secondary">{cve.package_version || ''}</Typography>
                                                        </TableCell>
                                                        <TableCell align="center">
                                                            <Typography variant="body2" fontWeight="bold">
                                                                {cve.cvss_score?.toFixed(1) || '—'}
                                                            </Typography>
                                                        </TableCell>
                                                        <TableCell>
                                                            <Chip
                                                                label={cve.severity || 'unknown'}
                                                                size="small"
                                                                color={
                                                                    cve.severity === 'critical' ? 'error' :
                                                                    cve.severity === 'high' ? 'warning' :
                                                                    cve.severity === 'medium' ? 'info' : 'default'
                                                                }
                                                            />
                                                        </TableCell>
                                                        <TableCell>
                                                            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                                                {cve.description || '—'}
                                                            </Typography>
                                                        </TableCell>
                                                    </TableRow>
                                                ))}
                                            </TableBody>
                                        </Table>
                                    </TableContainer>
                                </Box>
                            )}
                        </Box>
                    ) : (
                        <Typography color="error">Failed to load scan details.</Typography>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setDetailOpen(false)}>Close</Button>
                    {detail && (
                        <Button
                            variant="outlined"
                            startIcon={<History />}
                            onClick={() => {
                                setDetailOpen(false);
                                navigate(`/ledger?scan_id=${detail.id}`);
                            }}
                        >
                            View Ledger Entries
                        </Button>
                    )}
                </DialogActions>
            </Dialog>
        </Container>
    );
};

export default ScanHistory;
