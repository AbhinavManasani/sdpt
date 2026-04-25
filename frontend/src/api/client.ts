/**
 * Software Provenance Tracker — React API Client
 * 
 * Centralized axios-based API client for interacting with the backend.
 * Provides typed methods for all backend endpoints.
 */

import axios from 'axios';

// Base URL for the FastAPI backend
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';

const apiClient = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});
apiClient.defaults.headers.common['X-API-Key'] = import.meta.env.VITE_API_KEY || 'sdpt-dev-key-2024';

export const api = {
    // ─── Health ────────────────────────────────────────────────
    health: {
        check: async () => {
            const response = await axios.get('http://localhost:8000/health');
            return response.data;
        },
    },

    // ─── Dependencies ──────────────────────────────────────────

    dependencies: {
        scan: async (content: string, fileType: string, projectName: string = 'unnamed') => {
            const response = await apiClient.post('/dependencies/scan', {
                content,
                file_type: fileType,
                project_name: projectName,
            });
            return response.data;
        },

        getGraph: async (ecosystem: string, packageName: string) => {
            const response = await apiClient.get(`/dependencies/graph/${ecosystem}/${packageName}`);
            return response.data;
        },

        getHistory: async () => {
            const response = await apiClient.get('/dependencies/history');
            return response.data;
        },

        getScanDetail: async (id: number) => {
            const response = await apiClient.get(`/dependencies/history/${id}`);
            return response.data;
        },
    },

    // ─── Contributors ──────────────────────────────────────────

    contributors: {
        analyze: async (username: string) => {
            const response = await apiClient.post('/contributors/analyze', { username });
            return response.data;
        },

        analyzeRepo: async (owner: string, repo: string, ecosystem: string = 'pypi') => {
            const response = await apiClient.post('/contributors/analyze-repo', { owner, repo, ecosystem });
            return response.data;
        },

        getBaseline: async (username: string) => {
            const response = await apiClient.get(`/contributors/baseline/${username}`);
            return response.data;
        },
    },

    // ─── Anomaly Detection ─────────────────────────────────────

    anomaly: {
        score: async (features: Record<string, number>) => {
            const response = await apiClient.post('/anomaly/score', features);
            return response.data;
        },

        train: async () => {
            const response = await apiClient.post('/anomaly/train');
            return response.data;
        },

        getStatus: async () => {
            const response = await apiClient.get('/anomaly/status');
            return response.data;
        },

        getAttacks: async () => {
            const response = await apiClient.get('/anomaly/attacks');
            return response.data;
        },
    },

    // ─── Ledger ────────────────────────────────────────────────

    ledger: {
        record: async (data: any) => {
            const response = await apiClient.post('/ledger/record', data);
            return response.data;
        },

        getEntry: async (id: number) => {
            const response = await apiClient.get(`/ledger/entry/${id}`);
            return response.data;
        },

        getPackageHistory: async (packageName: string, ecosystem?: string) => {
            const response = await apiClient.get(`/ledger/package/${packageName}`, {
                params: { ecosystem },
            });
            return response.data;
        },

        getRecent: async (limit: number = 50, scanId?: number) => {
            const response = await apiClient.get('/ledger/recent', {
                params: { limit, ...(scanId !== undefined ? { scan_id: scanId } : {}) },
            });
            return response.data;
        },

        getFlagged: async (limit: number = 50) => {
            const response = await apiClient.get('/ledger/flagged', { params: { limit } });
            return response.data;
        },

        verifyChain: async (limit: number = 0) => {
            const response = await apiClient.get('/ledger/verify', { params: { limit } });
            return response.data;
        },

        getStats: async () => {
            const response = await apiClient.get('/ledger/stats');
            return response.data;
        },
    },

    // ─── Alerts ────────────────────────────────────────────────

    alerts: {
        generateFromAnomaly: async (data: any) => {
            const response = await apiClient.post('/alerts/generate/anomaly', data);
            return response.data;
        },

        generateFromContributor: async (data: any) => {
            const response = await apiClient.post('/alerts/generate/contributor', data);
            return response.data;
        },

        list: async (params?: { status?: string; severity?: string; package_name?: string; limit?: number; offset?: number }) => {
            const response = await apiClient.get('/alerts/', { params });
            return response.data;
        },

        getStats: async () => {
            const response = await apiClient.get('/alerts/stats');
            return response.data;
        },

        getById: async (id: number) => {
            const response = await apiClient.get(`/alerts/${id}`);
            return response.data;
        },

        updateStatus: async (id: number, status: string) => {
            const response = await apiClient.patch(`/alerts/${id}/status`, { status });
            return response.data;
        },

        bulkUpdateStatus: async (alertIds: number[], status: string) => {
            const response = await apiClient.patch('/alerts/bulk/status', {
                alert_ids: alertIds,
                status,
            });
            return response.data;
        },
    },

    // ─── CVE ───────────────────────────────────────────────────

    cve: {
        getByScan: async (scanId: number) => {
            const response = await apiClient.get(`/cve/scan/${scanId}`);
            return response.data;
        },

        checkPackage: async (packageName: string, ecosystem: string) => {
            const response = await apiClient.post('/cve/check', {
                package_name: packageName,
                ecosystem: ecosystem,
            });
            return response.data;
        },

        getStats: async () => {
            const response = await apiClient.get('/cve/stats');
            return response.data;
        },
    },

    // ─── Typosquat ────────────────────────────────────────────
    typosquat: {
        checkSingle: async (packageName: string, ecosystem: string) => {
            const response = await apiClient.post('/typosquat/check/single', {
                package_name: packageName,
                ecosystem: ecosystem,
            });
            return response.data;
        },
    },

    // ─── Trends ───────────────────────────────────────────────
    trends: {
        getStats: async (range: string = '30d') => {
            const response = await apiClient.get('/trends/stats', { params: { range } });
            return response.data;
        },

        getTimeline: async (entityType: string, entityName: string, days: number = 90) => {
            const response = await apiClient.get('/trends/timeline', {
                params: { entity_type: entityType, entity_name: entityName, days },
            });
            return response.data;
        },

        getTopMovers: async (entityType: string = 'package', days: number = 30, limit: number = 20) => {
            const response = await apiClient.get('/trends/top-movers', {
                params: { entity_type: entityType, days, limit },
            });
            return response.data;
        },

        getRiskBreakdown: async (entityType: string = 'package', days: number = 7) => {
            const response = await apiClient.get('/trends/risk-breakdown', {
                params: { entity_type: entityType, days },
            });
            return response.data;
        },
    },

    // ─── Monitor ──────────────────────────────────────────────
    monitor: {
        getFeed: async (limit: number = 50) => {
            const response = await apiClient.get('/monitor/feed', { params: { limit } });
            return response.data;
        },

        getStatus: async () => {
            const response = await apiClient.get('/monitor/status');
            return response.data;
        },

        start: async () => {
            const response = await apiClient.post('/monitor/start');
            return response.data;
        },

        stop: async () => {
            const response = await apiClient.post('/monitor/stop');
            return response.data;
        },
    },
    // ─── AI ───────────────────────────────────────────────────
    ai: {
        explain: async (alertId: number) => {
            const response = await apiClient.post(`/ai/explain/${alertId}`);
            return response.data;
        },
    },
};

export default api;
