import React, { useState } from 'react';
import {
    Container, Typography, Paper, Box, TextField,
    Button, FormControl, InputLabel, Select, MenuItem,
    CircularProgress, Chip, Grid, Card, CardContent, Divider,
    ToggleButton, ToggleButtonGroup,
    TableContainer, Table, TableHead, TableRow, TableCell, TableBody
} from '@mui/material';
import { Search, BugReport, VerifiedUser, AccountTree, CheckCircle } from '@mui/icons-material';
import api from '../api/client';

export const Scanner: React.FC = () => {
    const [scanMode, setScanMode] = useState<'quick' | 'file'>('quick');

    // Quick Scan State
    const [quickPackageName, setQuickPackageName] = useState('');
    const [quickVersion, setQuickVersion] = useState('');
    const [quickEcosystem, setQuickEcosystem] = useState('pypi');

    // File Scan State
    const [fileType, setFileType] = useState('requirements.txt');
    const [content, setContent] = useState('requests==2.31.0\n');

    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState('');

    const handleScan = async () => {
        let finalContent = content;
        let finalFileType = fileType;
        let finalProjectName = 'unnamed';

        if (scanMode === 'quick') {
            if (!quickPackageName.trim()) {
                setError('Please enter a package name for Quick Scan.');
                return;
            }
            finalProjectName = quickPackageName;

            if (quickEcosystem === 'pypi') {
                finalFileType = 'requirements.txt';
                finalContent = quickVersion.trim()
                    ? `${quickPackageName}==${quickVersion.trim()}`
                    : quickPackageName;
            } else {
                finalFileType = 'package.json';
                finalContent = JSON.stringify({
                    dependencies: {
                        [quickPackageName]: quickVersion.trim() || '*'
                    }
                });
            }
        } else {
            if (!content.trim()) {
                setError('Please enter at least one requirement to scan.');
                return;
            }
        }

        setLoading(true);
        setError('');
        setResult(null);

        try {
            const data = await api.dependencies.scan(finalContent, finalFileType, finalProjectName);
            setResult(data);
        } catch (err: any) {
            console.error(err);
            const detail = err.response?.data?.detail;
            const errorMsg = Array.isArray(detail)
                ? detail.map((d: any) => d.msg).join(', ')
                : (typeof detail === 'string' ? detail : err.message || 'An error occurred during scanning.');
            setError(errorMsg);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
            <Box mb={4} display="flex" alignItems="center" gap={2}>
                <AccountTree color="primary" sx={{ fontSize: 40 }} />
                <Box>
                    <Typography variant="h4" fontWeight="bold" color="primary.main">
                        Dependency Scanner
                    </Typography>
                    <Typography variant="subtitle1" color="text.secondary">
                        Analyze direct and transitive dependencies for vulnerabilities and anomalies.
                    </Typography>
                </Box>
            </Box>

            <Grid container spacing={4}>
                {/* ─── Scanner Form ────────────────────────────────────────── */}
                <Grid item xs={12} md={5}>
                    <Paper sx={{ p: 4, borderRadius: 2, boxShadow: 3 }}>
                        <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
                            <Typography variant="h6" fontWeight="bold">
                                Scan Configuration
                            </Typography>
                        </Box>

                        <ToggleButtonGroup
                            color="primary"
                            value={scanMode}
                            exclusive
                            onChange={(e, newMode) => { if (newMode) setScanMode(newMode); }}
                            fullWidth
                            sx={{ mb: 3 }}
                        >
                            <ToggleButton value="quick" sx={{ fontWeight: 'bold' }}>Quick Scan</ToggleButton>
                            <ToggleButton value="file" sx={{ fontWeight: 'bold' }}>File Scan</ToggleButton>
                        </ToggleButtonGroup>

                        {scanMode === 'quick' ? (
                            <Box>
                                <FormControl fullWidth sx={{ mb: 3 }}>
                                    <InputLabel id="quick-ecosystem-label">Ecosystem</InputLabel>
                                    <Select
                                        labelId="quick-ecosystem-label"
                                        value={quickEcosystem}
                                        label="Ecosystem"
                                        onChange={(e) => setQuickEcosystem(e.target.value)}
                                    >
                                        <MenuItem value="pypi">PyPI (Python)</MenuItem>
                                        <MenuItem value="npm">npm (Node.js)</MenuItem>
                                    </Select>
                                </FormControl>

                                <TextField
                                    fullWidth
                                    variant="outlined"
                                    label="Package Name"
                                    placeholder={quickEcosystem === 'pypi' ? "requests" : "react"}
                                    value={quickPackageName}
                                    onChange={(e) => setQuickPackageName(e.target.value)}
                                    sx={{ mb: 3 }}
                                />

                                <TextField
                                    fullWidth
                                    variant="outlined"
                                    label="Version (Optional)"
                                    placeholder={quickEcosystem === 'pypi' ? "2.31.0" : "18.2.0"}
                                    value={quickVersion}
                                    onChange={(e) => setQuickVersion(e.target.value)}
                                    sx={{ mb: 3 }}
                                />
                            </Box>
                        ) : (
                            <Box>
                                <FormControl fullWidth sx={{ mb: 3 }}>
                                    <InputLabel id="filetype-label">File Type</InputLabel>
                                    <Select
                                        labelId="filetype-label"
                                        value={fileType}
                                        label="File Type"
                                        onChange={(e) => setFileType(e.target.value)}
                                    >
                                        <MenuItem value="requirements.txt">requirements.txt (PyPI)</MenuItem>
                                        <MenuItem value="pyproject.toml">pyproject.toml (PyPI)</MenuItem>
                                        <MenuItem value="package.json">package.json (npm)</MenuItem>
                                        <MenuItem value="package-lock.json">package-lock.json (npm)</MenuItem>
                                    </Select>
                                </FormControl>

                                <TextField
                                    fullWidth
                                    multiline
                                    rows={8}
                                    variant="outlined"
                                    label="Requirements List"
                                    placeholder={fileType.includes('py') || fileType.includes('requirements') ? "requests==2.31.0\nfastapi>=0.100.0" : "react@18.2.0\nexpress@4.18.2"}
                                    value={content}
                                    onChange={(e) => setContent(e.target.value)}
                                    sx={{ mb: 3, fontFamily: 'monospace' }}
                                />
                            </Box>
                        )}

                        {error && (
                            <Typography color="error" variant="body2" sx={{ mb: 2 }}>
                                {error}
                            </Typography>
                        )}

                        <Button
                            fullWidth
                            variant="contained"
                            color="primary"
                            size="large"
                            onClick={handleScan}
                            disabled={loading}
                            startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <Search />}
                            sx={{ mt: 1, py: 1.5, fontWeight: 'bold' }}
                        >
                            {loading ? 'Analyzing...' : 'Start Deep Scan'}
                        </Button>
                    </Paper>
                </Grid>

                {/* ─── Scan Results ────────────────────────────────────────── */}
                <Grid item xs={12} md={7}>
                    <Paper sx={{ p: 0, borderRadius: 2, boxShadow: 3, height: '100%', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                        <Box sx={{ p: 3, bgcolor: 'primary.dark', color: 'white' }}>
                            <Typography variant="h6" fontWeight="bold">
                                Scan Report
                            </Typography>
                        </Box>

                        <Box sx={{ p: 3, flexGrow: 1, overflowY: 'auto', bgcolor: 'background.paper' }}>
                            {!result && !loading && (
                                <Box display="flex" flexDirection="column" alignItems="center" justifyContent="center" height="100%" color="text.secondary" opacity={0.6}>
                                    <AccountTree sx={{ fontSize: 80, mb: 2 }} />
                                    <Typography variant="h6">Ready to scan</Typography>
                                    <Typography>Configure scan parameters and start analysis.</Typography>
                                </Box>
                            )}

                            {loading && (
                                <Box display="flex" flexDirection="column" alignItems="center" justifyContent="center" height="100%">
                                    <CircularProgress size={60} thickness={4} />
                                    <Typography sx={{ mt: 3, color: 'text.secondary' }}>Traversing dependency graph...</Typography>
                                </Box>
                            )}

                            {result && (
                                <Box>
                                    <Grid container spacing={2} sx={{ mb: 4 }}>
                                        <Grid item xs={6}>
                                            <Card variant="outlined" sx={{ bgcolor: 'success.light', color: 'success.contrastText' }}>
                                                <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                                                    <Typography variant="overline" fontWeight="bold">Total Packages</Typography>
                                                    <Typography variant="h4" fontWeight="bold">
                                                        {result.total_packages || 0}
                                                    </Typography>
                                                </CardContent>
                                            </Card>
                                        </Grid>
                                        <Grid item xs={6}>
                                            <Card variant="outlined" sx={{
                                                bgcolor: 'info.light',
                                                color: 'info.contrastText'
                                            }}>
                                                <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                                                    <Typography variant="overline" fontWeight="bold">Direct Dependencies</Typography>
                                                    <Typography variant="h4" fontWeight="bold">
                                                        {result.direct_dependencies || 0}
                                                    </Typography>
                                                </CardContent>
                                            </Card>
                                        </Grid>
                                    </Grid>
                                    {/* ─── Summary Row ──────────────────────────────── */}
                                    <Box display="flex" gap={2} alignItems="center" flexWrap="wrap" mb={3}>
                                        <Chip
                                            label={`${result.scan_duration_seconds?.toFixed(2) || '0.00'}s`}
                                            size="small"
                                            variant="outlined"
                                        />
                                        <Chip
                                            label={result.ecosystem || 'unknown'}
                                            size="small"
                                            color="primary"
                                        />
                                        <Chip
                                            label={result.status || 'completed'}
                                            size="small"
                                            color={result.status === 'completed' ? 'success' : 'warning'}
                                        />
                                    </Box>

                                    {/* ─── Anomaly Summary ────────────────────────────── */}
                                    {result.anomaly_summary && (
                                        <Box mb={3}>
                                            <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                                                Anomaly Analysis
                                            </Typography>
                                            <Box display="flex" gap={2} flexWrap="wrap">
                                                <Chip
                                                    label={`Packages Scored: ${result.anomaly_summary.packages_scored}`}
                                                    size="small"
                                                    variant="outlined"
                                                />
                                                <Chip
                                                    label={`High Risk: ${result.anomaly_summary.high_risk}`}
                                                    size="small"
                                                    color={result.anomaly_summary.high_risk > 0 ? 'error' : 'default'}
                                                    variant={result.anomaly_summary.high_risk > 0 ? 'filled' : 'outlined'}
                                                />
                                                <Chip
                                                    label={`Critical Risk: ${result.anomaly_summary.critical_risk}`}
                                                    size="small"
                                                    color={result.anomaly_summary.critical_risk > 0 ? 'error' : 'default'}
                                                    variant={result.anomaly_summary.critical_risk > 0 ? 'filled' : 'outlined'}
                                                />
                                                <Chip
                                                    label={`Alerts Generated: ${result.anomaly_summary.alerts_generated}`}
                                                    size="small"
                                                    color={result.anomaly_summary.alerts_generated > 0 ? 'warning' : 'default'}
                                                    variant={result.anomaly_summary.alerts_generated > 0 ? 'filled' : 'outlined'}
                                                />
                                            </Box>
                                        </Box>
                                    )}

                                    <Divider sx={{ mb: 2 }} />

                                    {/* ─── Packages Table ─────────────────────────────── */}
                                    <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                                        Resolved Packages ({result.packages?.length || 0})
                                    </Typography>
                                    <TableContainer sx={{ maxHeight: 400 }}>
                                        <Table size="small" stickyHeader>
                                            <TableHead>
                                                <TableRow>
                                                    <TableCell sx={{ fontWeight: 'bold' }}>Package</TableCell>
                                                    <TableCell sx={{ fontWeight: 'bold' }}>Type</TableCell>
                                                    <TableCell sx={{ fontWeight: 'bold' }}>License</TableCell>
                                                    <TableCell sx={{ fontWeight: 'bold' }}>Author</TableCell>
                                                    <TableCell sx={{ fontWeight: 'bold' }} align="center">CVEs</TableCell>
                                                    <TableCell sx={{ fontWeight: 'bold' }} align="center">Anomaly</TableCell>
                                                </TableRow>
                                            </TableHead>
                                            <TableBody>
                                                {(result.packages || []).map((pkg: any, idx: number) => (
                                                    <TableRow key={idx} hover>
                                                        <TableCell>
                                                            <Typography variant="body2" fontWeight="bold">
                                                                {pkg.name}
                                                            </Typography>
                                                            <Typography variant="caption" color="text.secondary">
                                                                {pkg.version || 'latest'}
                                                            </Typography>
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
                                                            <Typography variant="body2" color="text.secondary">
                                                                {pkg.license || '—'}
                                                            </Typography>
                                                        </TableCell>
                                                        <TableCell>
                                                            <Typography variant="body2" color="text.secondary">
                                                                {pkg.author || '—'}
                                                            </Typography>
                                                        </TableCell>
                                                        <TableCell align="center">
                                                            {pkg.cve_count > 0 ? (
                                                                <Chip
                                                                    label={`${pkg.cve_count} CVE${pkg.cve_count > 1 ? 's' : ''}`}
                                                                    size="small"
                                                                    color={pkg.cve_count_critical > 0 ? 'error' :
                                                                           pkg.cve_count_high > 0 ? 'warning' : 'default'}
                                                                />
                                                            ) : (
                                                                <CheckCircle color="success" fontSize="small" />
                                                            )}
                                                        </TableCell>
                                                        <TableCell align="center">
                                                            <CheckCircle color="success" fontSize="small" />
                                                        </TableCell>
                                                    </TableRow>
                                                ))}
                                            </TableBody>
                                        </Table>
                                    </TableContainer>
                                </Box>
                            )}
                        </Box>
                    </Paper>
                </Grid>
            </Grid>
        </Container>
    );
};

export default Scanner;
