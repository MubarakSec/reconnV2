/**
 * ReconnV2 Dashboard JavaScript
 * Real-time updates and interactivity
 */

// ============================================
// Configuration
// ============================================
const CONFIG = {
    refreshInterval: 30000, // 30 seconds
    apiBaseUrl: '/api',
    toastDuration: 5000,
};

// ============================================
// State Management
// ============================================
const state = {
    isLoading: false,
    autoRefresh: true,
    refreshTimer: null,
    jobs: [],
    stats: null,
};

// ============================================
// Utility Functions
// ============================================

/**
 * Format date to Arabic locale
 */
function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleString('ar-SA', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * Format duration in human-readable format
 */
function formatDuration(seconds) {
    if (!seconds || seconds < 0) return '-';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hours > 0) {
        return `${hours}س ${minutes}د`;
    } else if (minutes > 0) {
        return `${minutes}د ${secs}ث`;
    } else {
        return `${secs}ث`;
    }
}

/**
 * Format number with Arabic numerals option
 */
function formatNumber(num) {
    if (num === undefined || num === null) return '0';
    return new Intl.NumberFormat('en-US').format(num);
}

/**
 * Debounce function for search/filter
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// ============================================
// API Functions
// ============================================

/**
 * Generic API request handler
 */
async function apiRequest(endpoint, options = {}) {
    try {
        const response = await fetch(`${CONFIG.apiBaseUrl}${endpoint}`, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`API Error [${endpoint}]:`, error);
        throw error;
    }
}

/**
 * Fetch dashboard stats
 */
async function fetchStats() {
    return await apiRequest('/stats');
}

/**
 * Fetch jobs list
 */
async function fetchJobs(status = 'all') {
    return await apiRequest(`/jobs?status=${status}`);
}

/**
 * Fetch job details
 */
async function fetchJobDetails(jobId) {
    return await apiRequest(`/jobs/${jobId}`);
}

/**
 * Start a new scan
 */
async function startScan(formData) {
    return await apiRequest('/scan', {
        method: 'POST',
        body: JSON.stringify(formData)
    });
}

// ============================================
// UI Update Functions
// ============================================

/**
 * Update stats cards
 */
function updateStatsCards(stats) {
    if (!stats) return;
    
    const elements = {
        'total-jobs': stats.total_jobs || 0,
        'running-jobs': stats.running || 0,
        'finished-jobs': stats.finished || 0,
        'failed-jobs': stats.failed || 0,
        'total-hosts': stats.total_hosts || 0,
        'total-vulns': stats.total_vulnerabilities || 0,
    };
    
    Object.entries(elements).forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el) {
            animateValue(el, parseInt(el.textContent) || 0, value, 500);
        }
    });
    
    state.stats = stats;
}

/**
 * Animate number counting
 */
function animateValue(element, start, end, duration) {
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = Math.floor(start + (end - start) * easeOut);
        
        element.textContent = formatNumber(current);
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

/**
 * Update jobs table
 */
function updateJobsTable(jobs) {
    const tbody = document.getElementById('jobs-table-body');
    if (!tbody) return;
    
    if (!jobs || jobs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-5">
                    <div class="empty-state">
                        <i class="bi bi-inbox"></i>
                        <h3>لا توجد مهام</h3>
                        <p>ابدأ فحصاً جديداً للبدء</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = jobs.map(job => `
        <tr>
            <td>
                <a href="/jobs/${job.id}" class="text-decoration-none fw-semibold">
                    ${job.id}
                </a>
            </td>
            <td>${job.target || '-'}</td>
            <td>
                <span class="status-badge ${job.status}">${getStatusText(job.status)}</span>
            </td>
            <td>${formatDate(job.created_at)}</td>
            <td>${formatDuration(job.duration)}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <a href="/jobs/${job.id}" class="btn btn-outline-primary" title="عرض التفاصيل">
                        <i class="bi bi-eye"></i>
                    </a>
                    <a href="/jobs/${job.id}/report" class="btn btn-outline-success" title="تحميل التقرير">
                        <i class="bi bi-file-earmark-text"></i>
                    </a>
                </div>
            </td>
        </tr>
    `).join('');
    
    state.jobs = jobs;
}

/**
 * Get status text in Arabic
 */
function getStatusText(status) {
    const statusMap = {
        'running': 'قيد التشغيل',
        'finished': 'مكتمل',
        'failed': 'فشل',
        'queued': 'في الانتظار',
    };
    return statusMap[status] || status;
}

// ============================================
// Loading & Spinner
// ============================================

/**
 * Show loading overlay
 */
function showLoading() {
    state.isLoading = true;
    let overlay = document.getElementById('loading-overlay');
    
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'loading-overlay';
        overlay.className = 'spinner-overlay';
        overlay.innerHTML = '<div class="spinner"></div>';
        document.body.appendChild(overlay);
    }
    
    overlay.style.display = 'flex';
}

/**
 * Hide loading overlay
 */
function hideLoading() {
    state.isLoading = false;
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

// ============================================
// Toast Notifications
// ============================================

/**
 * Show toast notification
 */
function showToast(message, type = 'success') {
    let container = document.getElementById('toast-container');
    
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    
    const icons = {
        success: 'bi-check-circle-fill',
        error: 'bi-x-circle-fill',
        warning: 'bi-exclamation-triangle-fill',
        info: 'bi-info-circle-fill'
    };
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <i class="bi ${icons[type] || icons.info}"></i>
        <span>${message}</span>
        <button class="btn-close btn-close-sm ms-2" onclick="this.parentElement.remove()"></button>
    `;
    
    container.appendChild(toast);
    
    // Auto remove after duration
    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, CONFIG.toastDuration);
}

// ============================================
// Form Handling
// ============================================

/**
 * Initialize scan form
 */
function initScanForm() {
    const form = document.getElementById('scan-form');
    if (!form) return;
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = {
            target: document.getElementById('target').value,
            profile: document.getElementById('profile').value,
            scanMode: document.getElementById('scanMode') ? document.getElementById('scanMode').value : 'queued',
        };

        if (!formData.target) {
            showToast('الرجاء إدخال الهدف', 'error');
            return;
        }

        try {
            showLoading();
            const result = await startScan(formData);
            showToast('تم بدء الفحص بنجاح!', 'success');

            // Redirect to job page or refresh
            if (result.job_id) {
                window.location.href = `/jobs/${result.job_id}`;
            } else {
                refreshData();
            }
        } catch (error) {
            showToast('فشل بدء الفحص: ' + error.message, 'error');
        } finally {
            hideLoading();
        }
    });
}

// ============================================
// Auto Refresh
// ============================================

/**
 * Start auto refresh
 */
function startAutoRefresh() {
    if (state.refreshTimer) {
        clearInterval(state.refreshTimer);
    }
    
    state.refreshTimer = setInterval(() => {
        if (state.autoRefresh && !state.isLoading) {
            refreshData();
        }
    }, CONFIG.refreshInterval);
}

/**
 * Stop auto refresh
 */
function stopAutoRefresh() {
    if (state.refreshTimer) {
        clearInterval(state.refreshTimer);
        state.refreshTimer = null;
    }
}

/**
 * Toggle auto refresh
 */
function toggleAutoRefresh() {
    state.autoRefresh = !state.autoRefresh;
    const btn = document.getElementById('auto-refresh-btn');
    
    if (btn) {
        btn.innerHTML = state.autoRefresh 
            ? '<i class="bi bi-pause-fill"></i> إيقاف التحديث'
            : '<i class="bi bi-play-fill"></i> تشغيل التحديث';
        btn.classList.toggle('btn-outline-secondary', !state.autoRefresh);
        btn.classList.toggle('btn-outline-primary', state.autoRefresh);
    }
    
    showToast(state.autoRefresh ? 'تم تفعيل التحديث التلقائي' : 'تم إيقاف التحديث التلقائي', 'info');
}

/**
 * Refresh all data
 */
async function refreshData() {
    try {
        const [stats, jobs] = await Promise.all([
            fetchStats().catch(() => null),
            fetchJobs().catch(() => [])
        ]);
        
        if (stats) updateStatsCards(stats);
        if (jobs) updateJobsTable(jobs);
        
        // Update last refresh time
        const lastUpdate = document.getElementById('last-update');
        if (lastUpdate) {
            lastUpdate.textContent = new Date().toLocaleTimeString('ar-SA');
        }
    } catch (error) {
        console.error('Refresh error:', error);
    }
}

// ============================================
// Search & Filter
// ============================================

/**
 * Initialize search functionality
 */
function initSearch() {
    const searchInput = document.getElementById('search-input');
    if (!searchInput) return;
    
    const searchHandler = debounce((e) => {
        const query = e.target.value.toLowerCase();
        filterJobs(query);
    }, 300);
    
    searchInput.addEventListener('input', searchHandler);
}

/**
 * Filter jobs table
 */
function filterJobs(query) {
    const rows = document.querySelectorAll('#jobs-table-body tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
    });
}

/**
 * Initialize status filter
 */
function initStatusFilter() {
    const filter = document.getElementById('status-filter');
    if (!filter) return;
    
    filter.addEventListener('change', async (e) => {
        const status = e.target.value;
        try {
            showLoading();
            const jobs = await fetchJobs(status);
            updateJobsTable(jobs);
        } catch (error) {
            showToast('فشل تحميل المهام', 'error');
        } finally {
            hideLoading();
        }
    });
}

// ============================================
// Job Details Page
// ============================================

/**
 * Initialize job details page
 */
function initJobDetails() {
    const jobId = document.getElementById('job-id')?.dataset.jobId;
    if (!jobId) return;
    
    // Load job details
    loadJobDetails(jobId);
    
    // Initialize tabs
    initTabs();
}

/**
 * Load job details
 */
async function loadJobDetails(jobId) {
    try {
        showLoading();
        const job = await fetchJobDetails(jobId);
        updateJobDetails(job);
    } catch (error) {
        showToast('فشل تحميل تفاصيل المهمة', 'error');
    } finally {
        hideLoading();
    }
}

/**
 * Update job details UI
 */
function updateJobDetails(job) {
    if (!job) return;
    
    // Update header info
    const elements = {
        'job-target': job.target,
        'job-status': getStatusText(job.status),
        'job-created': formatDate(job.created_at),
        'job-duration': formatDuration(job.duration),
        'job-profile': job.profile,
    };
    
    Object.entries(elements).forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    });
    
    // Update status badge class
    const statusBadge = document.getElementById('job-status');
    if (statusBadge) {
        statusBadge.className = `status-badge ${job.status}`;
    }
}

/**
 * Initialize tabs
 */
function initTabs() {
    const tabs = document.querySelectorAll('[data-bs-toggle="tab"]');
    tabs.forEach(tab => {
        tab.addEventListener('shown.bs.tab', (e) => {
            const target = e.target.getAttribute('data-bs-target');
            loadTabContent(target);
        });
    });
}

/**
 * Load tab content
 */
async function loadTabContent(tabId) {
    const jobId = document.getElementById('job-id')?.dataset.jobId;
    if (!jobId) return;
    
    const contentMap = {
        '#hosts-tab': 'hosts',
        '#urls-tab': 'urls',
        '#vulns-tab': 'vulnerabilities',
        '#secrets-tab': 'secrets'
    };
    
    const contentType = contentMap[tabId];
    if (!contentType) return;
    
    try {
        const data = await apiRequest(`/jobs/${jobId}/${contentType}`);
        updateTabContent(tabId, data);
    } catch (error) {
        console.error(`Failed to load ${contentType}:`, error);
    }
}

/**
 * Update tab content
 */
function updateTabContent(tabId, data) {
    const container = document.querySelector(`${tabId} .content`);
    if (!container || !data) return;
    
    if (data.length === 0) {
        container.innerHTML = '<p class="text-muted text-center py-4">لا توجد بيانات</p>';
        return;
    }
    
    // Render based on content type
    // This will be customized based on the data type
    container.innerHTML = data.map(item => `
        <div class="result-item">
            <div class="host">${item.host || item.url || item.name}</div>
            <div class="details">${item.details || item.description || ''}</div>
        </div>
    `).join('');
}

// ============================================
// Keyboard Shortcuts
// ============================================

/**
 * Initialize keyboard shortcuts
 */
function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + R - Refresh
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            refreshData();
            showToast('تم تحديث البيانات', 'info');
        }
        
        // Ctrl/Cmd + K - Focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.getElementById('search-input');
            if (searchInput) searchInput.focus();
        }
        
        // Escape - Close modals
        if (e.key === 'Escape') {
            const modals = document.querySelectorAll('.modal.show');
            modals.forEach(modal => {
                const instance = bootstrap.Modal.getInstance(modal);
                if (instance) instance.hide();
            });
        }
    });
}

// ============================================
// Clipboard Functions
// ============================================

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('تم النسخ إلى الحافظة', 'success');
    } catch (error) {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast('تم النسخ إلى الحافظة', 'success');
    }
}

// ============================================
// Export Functions
// ============================================

/**
 * Export data as JSON
 */
function exportAsJson(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `${filename}.json`);
}

/**
 * Export data as CSV
 */
function exportAsCsv(data, filename) {
    if (!data || data.length === 0) return;
    
    const headers = Object.keys(data[0]);
    const csvContent = [
        headers.join(','),
        ...data.map(row => headers.map(h => `"${row[h] || ''}"`).join(','))
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    downloadBlob(blob, `${filename}.csv`);
}

/**
 * Download blob as file
 */
function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ============================================
// Theme Toggle (Dark/Light Mode)
// ============================================

/**
 * Initialize theme
 */
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

/**
 * Toggle theme
 */
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
}

/**
 * Update theme icon
 */
function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.className = theme === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
    }
}

// ============================================
// Initialization
// ============================================

/**
 * Initialize dashboard
 */
function initDashboard() {
    // Core initialization
    initTheme();
    initScanForm();
    initSearch();
    initStatusFilter();
    initKeyboardShortcuts();
    
    // Start auto refresh
    startAutoRefresh();
    
    // Initial data load
    refreshData();
    
    // Page-specific initialization
    const pageType = document.body.dataset.page;
    if (pageType === 'job-detail') {
        initJobDetails();
    }
    
    console.log('🚀 ReconnV2 Dashboard initialized');
}

// Start when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDashboard);
} else {
    initDashboard();
}

// Export functions for global access
window.ReconnV2 = {
    refreshData,
    toggleAutoRefresh,
    copyToClipboard,
    exportAsJson,
    exportAsCsv,
    toggleTheme,
    showToast,
};
