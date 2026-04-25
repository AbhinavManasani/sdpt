import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
    Container, Typography, Paper, Box, CircularProgress,
    Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
    Chip, Button, Grid, IconButton, Tooltip, Dialog, DialogTitle,
    DialogContent, DialogActions, Divider
} from '@mui/material';
import { History, Security, Fingerprint, Refresh, CheckCircle, ErrorOutline, FilterList } from '@mui/icons-material';
import api from '../api/client';

export const Ledger: React.FC = () => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const scanIdParam = searchParams.get('scan_id');
    const activeScanId = scanIdParam ? parseInt(scanIdParam, 10) : undefined;

    const [entries, setEntries] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [verifying, setVerifying] = useState(false);
    const [verificationResult, setVerificationResult] = useState<any>(null);
    const [selectedEntry, setSelectedEntry] = useState<any | null>(null);

    const loadEntries = async () => {
        setLoading(true);
        try {
            const res = await api.ledger.getRecent(100, activeScanId);
            setEntries(res.entries || []);
        } catch (err) {
            console.error("Failed to load ledger entries:", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadEntries();
    }, [scanIdParam]);  // re-fetch when URL param changes

    const handleVerifyChain = async () => {
        setVerifying(true);
        setVerificationResult(null);
        try {
            const res = await api.ledger.verifyChain();
            setVerificationResult(res);
        } catch (err: any) {
            console.error("Chain verification failed:", err);
            setVerificationResult({
                verified: false,
                message: err.response?.data?.detail || "Verification failed"
            });
        } finally {
            setVerifying(false);
        }
    };

    // Helper to truncate long hashes for display
    const truncateHash = (hash: string) => {
        if (!hash) return "N/A";
        return `${hash.substring(0, 8)}...${hash.substring(hash.length - 8)}`;
    };

    return (
        <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
            <Box mb={4} display="flex" alignItems="center" justifyContent="space-between">
                <Box display="flex" alignItems="center" gap={2}>
                    <History color="info" sx={{ fontSize: 40 }} />
                    <Box>
                        <Typography variant="h4" fontWeight="bold" color="text.primary">
                            Provenance Ledger
                        </Typography>
                        <Typography variant="subtitle1" color="text.secondary">
                            Immutable supply chain record. Hash-chained verification.
                        </Typography>
                    </Box>
                </Box>

                <Box display="flex" gap={2}>
                    {activeScanId !== undefined && (
                        <Chip
                            icon={<FilterList />}
                            label={`Filtered by scan #${activeScanId}`}
                            color="primary"
                            variant="outlined"
                            onDelete={() => navigate('/ledger')}
                            sx={{ fontWeight: 'bold', alignSelf: 'center' }}
                        />
                    )}
                    <Button
                        variant="outlined"
                        color="primary"
                        startIcon={<Refresh />}
                        onClick={loadEntries}
                        disabled={loading || verifying}
                    >
                        Refresh List
                    </Button>
                    <Button
                        variant="contained"
                        color="secondary"
                        startIcon={verifying ? <CircularProgress size={20} color="inherit" /> : <Security />}
                        onClick={handleVerifyChain}
                        disabled={loading || verifying}
                    >
                        {verifying ? 'Verifying Chain...' : 'Verify Ledger Integrity'}
                    </Button>
                </Box>
            </Box>

            {/* Verification Status Banner */}
            {verificationResult && (
                <Paper
                    sx={{
                        p: 3, mb: 4,
                        bgcolor: verificationResult.status === 'verified' ? 'success.light' : 'error.light',
                        color: verificationResult.status === 'verified' ? 'success.contrastText' : 'error.contrastText',
                        display: 'flex', alignItems: 'center', gap: 2, borderRadius: 2
                    }}
                >
                    {verificationResult.status === 'verified' ? <CheckCircle fontSize="large" /> : <ErrorOutline fontSize="large" />}
                    <Box>
                        <Typography variant="h6" fontWeight="bold">
                            {verificationResult.status === 'verified' ? 'Ledger Chain Verified' : 'Integrity Violation Detected'}
                        </Typography>
                        <Typography variant="body1">
                            {verificationResult.message}
                            {verificationResult.status === 'verified' && ` (${verificationResult.entries_checked} entries checked)`}
                        </Typography>
                        {verificationResult.broken_at_id && (
                            <Typography variant="body2" sx={{ mt: 1, fontWeight: 'bold' }}>
                                Chain breaks at Entry #{verificationResult.broken_at_id}
                            </Typography>
                        )}
                    </Box>
                </Paper>
            )}

            <TableContainer component={Paper} sx={{ borderRadius: 2, boxShadow: 2 }}>
                <Table sx={{ minWidth: 800 }}>
                    <TableHead sx={{ bgcolor: 'background.default' }}>
                        <TableRow>
                            <TableCell><b>ID</b></TableCell>
                            <TableCell><b>Package</b></TableCell>
                            <TableCell><b>Published</b></TableCell>
                            <TableCell><b>Anomaly Score</b></TableCell>
                            <TableCell><b>Flags</b></TableCell>
                            <TableCell><b>Entry Hash (SHA-256)</b></TableCell>
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
                        ) : entries.length === 0 ? (
                            <TableRow>
                                <TableCell colSpan={7} align="center" sx={{ py: 6 }}>
                                    <Typography color="text.secondary">No ledger entries yet.</Typography>
                                </TableCell>
                            </TableRow>
                        ) : (
                            entries.map((entry) => (
                                <TableRow key={entry.id} hover>
                                    <TableCell>#{entry.id}</TableCell>
                                    <TableCell>
                                        <Typography variant="body2" fontWeight="bold">
                                            {entry.package_name} v{entry.package_version}
                                        </Typography>
                                        <Typography variant="caption" color="text.secondary">
                                            {entry.ecosystem} | User: {entry.publisher_github_id || 'Unknown'}
                                        </Typography>
                                    </TableCell>
                                    <TableCell>
                                        <Typography variant="body2">
                                            {new Date(entry.publish_timestamp).toLocaleString()}
                                        </Typography>
                                    </TableCell>
                                    <TableCell>
                                        {entry.anomaly_score !== null ? (
                                            <Chip
                                                label={`${entry.anomaly_score}/100`}
                                                color={entry.anomaly_score >= 80 ? 'error' : entry.anomaly_score >= 50 ? 'warning' : 'success'}
                                                size="small"
                                                variant="outlined"
                                                sx={{ fontWeight: 'bold' }}
                                            />
                                        ) : (
                                            <Typography variant="body2" color="text.secondary">N/A</Typography>
                                        )}
                                    </TableCell>
                                    <TableCell>
                                        {entry.flags_triggered && entry.flags_triggered.length > 0 ? (
                                            <Chip
                                                label={`${entry.flags_triggered.length} Flags`}
                                                color="error"
                                                size="small"
                                            />
                                        ) : (
                                            <Typography variant="body2" color="text.secondary">None</Typography>
                                        )}
                                    </TableCell>
                                    <TableCell>
                                        <Box display="flex" alignItems="center" gap={1}>
                                            <Fingerprint fontSize="small" color="disabled" />
                                            <Typography variant="body2" fontFamily="monospace" color="text.secondary">
                                                {truncateHash(entry.entry_hash)}
                                            </Typography>
                                        </Box>
                                    </TableCell>
                                    <TableCell align="right">
                                        <Button
                                            size="small"
                                            variant="outlined"
                                            onClick={() => setSelectedEntry(entry)}
                                        >
                                            View Details
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* ─── Detail Modal ────────────────────────────────────────── */}
            <Dialog
                open={!!selectedEntry}
                onClose={() => setSelectedEntry(null)}
                maxWidth="md"
                fullWidth
            >
                {selectedEntry && (
                    <>
                        <DialogTitle sx={{ borderBottom: 1, borderColor: 'divider', pb: 2 }}>
                            <Box display="flex" justifyContent="space-between" alignItems="center">
                                <Typography variant="h6" fontWeight="bold">
                                    Ledger Entry #{selectedEntry.id}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                    Recorded: {new Date(selectedEntry.created_at).toLocaleString()}
                                </Typography>
                            </Box>
                        </DialogTitle>
                        <DialogContent sx={{ p: 4 }}>
                            <Grid container spacing={4}>
                                <Grid item xs={12} sm={6}>
                                    <Typography variant="overline" color="text.secondary">Target Package</Typography>
                                    <Typography variant="h6" fontWeight="bold">
                                        {selectedEntry.package_name} v{selectedEntry.package_version}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" gutterBottom>
                                        Ecosystem: {selectedEntry.ecosystem}
                                    </Typography>
                                </Grid>

                                <Grid item xs={12} sm={6}>
                                    <Typography variant="overline" color="text.secondary">Publisher Identity</Typography>
                                    <Typography variant="h6">
                                        {selectedEntry.publisher_github_id || 'Anonymous / Unknown'}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" gutterBottom>
                                        Published At: {new Date(selectedEntry.publish_timestamp).toLocaleString()}
                                    </Typography>
                                </Grid>

                                <Grid item xs={12}>
                                    <Divider sx={{ my: 2 }} />
                                    <Typography variant="overline" color="text.secondary" gutterBottom display="block">
                                        Cryptographic Proofs
                                    </Typography>

                                    <Box sx={{ mb: 2 }}>
                                        <Typography variant="caption" color="text.secondary">Current Entry Hash</Typography>
                                        <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.100', p: 1, borderRadius: 1, wordBreak: 'break-all' }}>
                                            {selectedEntry.entry_hash}
                                        </Typography>
                                    </Box>

                                    <Box sx={{ mb: 2 }}>
                                        <Typography variant="caption" color="text.secondary">Previous Entry Hash</Typography>
                                        <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.100', p: 1, borderRadius: 1, wordBreak: 'break-all' }}>
                                            {selectedEntry.previous_entry_hash || 'GENESIS_BLOCK (None)'}
                                        </Typography>
                                    </Box>

                                    <Box sx={{ mb: 2 }}>
                                        <Typography variant="caption" color="text.secondary">Dependency Graph Hash</Typography>
                                        <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.100', p: 1, borderRadius: 1, wordBreak: 'break-all' }}>
                                            {selectedEntry.dependency_graph_hash}
                                        </Typography>
                                    </Box>

                                    {selectedEntry.source_commit_hash && (
                                        <Box sx={{ mb: 2 }}>
                                            <Typography variant="caption" color="text.secondary">Source Commit Hash</Typography>
                                            <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.100', p: 1, borderRadius: 1, wordBreak: 'break-all' }}>
                                                {selectedEntry.source_commit_hash}
                                            </Typography>
                                        </Box>
                                    )}

                                    {selectedEntry.build_artifact_hash && (
                                        <Box sx={{ mb: 2 }}>
                                            <Typography variant="caption" color="text.secondary">Build Artifact Hash</Typography>
                                            <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.100', p: 1, borderRadius: 1, wordBreak: 'break-all' }}>
                                                {selectedEntry.build_artifact_hash}
                                            </Typography>
                                        </Box>
                                    )}
                                </Grid>

                                {selectedEntry.flags_triggered && selectedEntry.flags_triggered.length > 0 && (
                                    <Grid item xs={12}>
                                        <Typography variant="overline" color="error" gutterBottom display="block">
                                            Anomaly Flags Triggered At Ingestion
                                        </Typography>
                                        <Box display="flex" gap={1} flexWrap="wrap">
                                            {selectedEntry.flags_triggered.map((flag: string, i: number) => (
                                                <Chip key={i} label={flag} color="error" variant="outlined" />
                                            ))}
                                        </Box>
                                    </Grid>
                                )}
                            </Grid>
                        </DialogContent>
                        <DialogActions sx={{ p: 2 }}>
                            <Button onClick={() => setSelectedEntry(null)} variant="outlined">
                                Close Overlay
                            </Button>
                        </DialogActions>
                    </>
                )}
            </Dialog>
        </Container>
    );
};

export default Ledger;
