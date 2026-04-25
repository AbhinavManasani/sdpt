import React, { useState, useMemo } from 'react';
import { BrowserRouter, Routes, Route, useNavigate, useLocation } from 'react-router-dom';
import {
    ThemeProvider, createTheme, CssBaseline,
    Box, Drawer, List, ListItem, ListItemButton,
    ListItemIcon, ListItemText, AppBar, Toolbar,
    Typography, IconButton, Divider, useMediaQuery, Button
} from '@mui/material';
import {
    Dashboard as DashboardIcon,
    AccountTree,
    Warning,
    History,
    Brightness4,
    Brightness7,
    Menu as MenuIcon,
    Security,
    ManageSearch,
    Hub,
    ShowChart,
    RssFeed
} from '@mui/icons-material';

// Import Pages
import { Dashboard } from './pages/Dashboard';
import { Scanner } from './pages/Scanner';
import { Alerts } from './pages/Alerts';
import { Ledger } from './pages/Ledger';
import { ScanHistory } from './pages/ScanHistory';
import { GraphView } from './pages/GraphView';
import { Trends } from './pages/Trends';
import { Monitor } from './pages/Monitor';

const drawerWidth = 260;

const NotFound: React.FC = () => {
    const navigate = useNavigate();
    return (
        <Box display="flex" flexDirection="column"
             alignItems="center" justifyContent="center"
             minHeight="60vh" gap={2}>
            <Typography variant="h1" fontWeight="bold"
                        color="text.secondary">404</Typography>
            <Typography variant="h5" color="text.secondary">
                Page not found
            </Typography>
            <Button variant="contained" onClick={() => navigate('/')}>
                Back to Dashboard
            </Button>
        </Box>
    );
};

const NavigationItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
    { text: 'Dependency Scanner', icon: <AccountTree />, path: '/scanner' },
    { text: 'Graph View', icon: <Hub />, path: '/graph' },
    { text: 'Scan History', icon: <ManageSearch />, path: '/history' },
    { text: 'Alert Management', icon: <Warning />, path: '/alerts' },
    { text: 'Provenance Ledger', icon: <History />, path: '/ledger' },
    { text: 'Trend Analysis', icon: <ShowChart />, path: '/trends' },
    { text: 'Feed Monitor', icon: <RssFeed />, path: '/monitor' },
];

const MainLayout: React.FC<{ toggleTheme: () => void; isDark: boolean }> = ({ toggleTheme, isDark }) => {
    const [mobileOpen, setMobileOpen] = useState(false);
    const navigate = useNavigate();
    const location = useLocation();

    const handleDrawerToggle = () => {
        setMobileOpen(!mobileOpen);
    };

    const drawer = (
        <div>
            <Toolbar sx={{ display: 'flex', alignItems: 'center', p: 2, gap: 1 }}>
                <Security color="primary" sx={{ fontSize: 32 }} />
                <Typography variant="h6" fontWeight="bold" noWrap component="div" sx={{ flexGrow: 1, lineHeight: 1.2 }}>
                    Provenance<br />
                    <Typography component="span" variant="caption" color="primary">Tracker</Typography>
                </Typography>
            </Toolbar>
            <Divider />
            <List sx={{ px: 1, py: 2 }}>
                {NavigationItems.map((item) => {
                    const selected = location.pathname === item.path;
                    return (
                        <ListItem key={item.text} disablePadding sx={{ mb: 0.5 }}>
                            <ListItemButton
                                selected={selected}
                                onClick={() => {
                                    navigate(item.path);
                                    if (mobileOpen) setMobileOpen(false);
                                }}
                                sx={{
                                    borderRadius: 2,
                                    '&.Mui-selected': {
                                        bgcolor: 'primary.main',
                                        color: 'primary.contrastText',
                                        '&:hover': {
                                            bgcolor: 'primary.dark',
                                        },
                                        '& .MuiListItemIcon-root': {
                                            color: 'primary.contrastText',
                                        }
                                    }
                                }}
                            >
                                <ListItemIcon sx={{ minWidth: 40, color: selected ? 'inherit' : 'text.secondary' }}>
                                    {item.icon}
                                </ListItemIcon>
                                <ListItemText
                                    primary={item.text}
                                    primaryTypographyProps={{ fontWeight: selected ? 'bold' : 'medium' }}
                                />
                            </ListItemButton>
                        </ListItem>
                    );
                })}
            </List>
        </div>
    );

    return (
        <Box sx={{ display: 'flex' }}>
            <CssBaseline />

            {/* ─── Application Header ──────────────────────────────────────── */}
            <AppBar
                position="fixed"
                elevation={0}
                sx={{
                    width: { sm: `calc(100% - ${drawerWidth}px)` },
                    ml: { sm: `${drawerWidth}px` },
                    bgcolor: 'background.paper',
                    color: 'text.primary',
                    borderBottom: 1,
                    borderColor: 'divider'
                }}
            >
                <Toolbar>
                    <IconButton
                        color="inherit"
                        aria-label="open drawer"
                        edge="start"
                        onClick={handleDrawerToggle}
                        sx={{ mr: 2, display: { sm: 'none' } }}
                    >
                        <MenuIcon />
                    </IconButton>

                    <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1, fontWeight: 'bold' }}>
                        {NavigationItems.find(item => item.path === location.pathname)?.text || 'Software Provenance Tracker'}
                    </Typography>

                    <IconButton onClick={toggleTheme} color="inherit" title="Toggle Light/Dark Theme">
                        {isDark ? <Brightness7 /> : <Brightness4 />}
                    </IconButton>
                </Toolbar>
            </AppBar>

            {/* ─── Sidebar Navigation ──────────────────────────────────────── */}
            <Box
                component="nav"
                sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
            >
                <Drawer
                    variant="temporary"
                    open={mobileOpen}
                    onClose={handleDrawerToggle}
                    ModalProps={{ keepMounted: true }} // Better open performance on mobile.
                    sx={{
                        display: { xs: 'block', sm: 'none' },
                        '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
                    }}
                >
                    {drawer}
                </Drawer>
                <Drawer
                    variant="permanent"
                    sx={{
                        display: { xs: 'none', sm: 'block' },
                        '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
                    }}
                    open
                >
                    {drawer}
                </Drawer>
            </Box>

            {/* ─── Main Content Area ───────────────────────────────────────── */}
            <Box
                component="main"
                sx={{
                    flexGrow: 1,
                    p: 0,
                    width: { sm: `calc(100% - ${drawerWidth}px)` },
                    minHeight: '100vh',
                    bgcolor: 'background.default'
                }}
            >
                <Toolbar /> {/* Spacer for AppBar */}
                <Box sx={{ p: 3 }}>
                    <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/scanner" element={<Scanner />} />
                        <Route path="/graph" element={<GraphView />} />
                        <Route path="/history" element={<ScanHistory />} />
                        <Route path="/alerts" element={<Alerts />} />
                        <Route path="/ledger" element={<Ledger />} />
                        <Route path="/trends" element={<Trends />} />
                        <Route path="/monitor" element={<Monitor />} />
                        <Route path="*" element={<NotFound />} />
                    </Routes>
                </Box>
            </Box>
        </Box>
    );
};

export const App: React.FC = () => {
    const prefersDarkMode = useMediaQuery('(prefers-color-scheme: dark)');
    const [mode, setMode] = useState<'light' | 'dark'>(prefersDarkMode ? 'dark' : 'light');

    const toggleTheme = () => {
        setMode((prevMode) => (prevMode === 'light' ? 'dark' : 'light'));
    };

    const theme = useMemo(
        () =>
            createTheme({
                palette: {
                    mode,
                    primary: {
                        main: mode === 'dark' ? '#90caf9' : '#1976d2',
                    },
                    secondary: {
                        main: mode === 'dark' ? '#f48fb1' : '#dc004e',
                    },
                    background: {
                        default: mode === 'dark' ? '#121212' : '#f5f7fa',
                        paper: mode === 'dark' ? '#1e1e1e' : '#ffffff',
                    },
                },
                typography: {
                    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
                    h4: { fontWeight: 700 },
                    h6: { fontWeight: 600 },
                    button: { textTransform: 'none', fontWeight: 600 }
                },
                components: {
                    MuiPaper: {
                        styleOverrides: {
                            root: {
                                backgroundImage: 'none',
                            }
                        }
                    },
                    MuiButton: {
                        styleOverrides: {
                            root: {
                                borderRadius: 8,
                            }
                        }
                    }
                }
            }),
        [mode],
    );

    return (
        <ThemeProvider theme={theme}>
            <BrowserRouter>
                <MainLayout toggleTheme={toggleTheme} isDark={mode === 'dark'} />
            </BrowserRouter>
        </ThemeProvider>
    );
};

export default App;