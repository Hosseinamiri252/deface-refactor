import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Server, Activity, Bell, FileText, Lock, HardDrive, Settings, Plus, RefreshCw, Eye, Shield } from 'lucide-react';

// API Configuration
const API_BASE_URL = 'http://localhost:8000/api';

// API Functions
const api = {
  // Dashboard
  getDashboardStats: async () => {
    const response = await fetch(`${API_BASE_URL}/dashboard/stats`);
    return response.json();
  },
  
  // Servers
  getServers: async () => {
    const response = await fetch(`${API_BASE_URL}/servers`);
    return response.json();
  },
  
  addServer: async (serverData) => {
    const response = await fetch(`${API_BASE_URL}/servers`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(serverData)
    });
    return response.json();
  },
  
  deleteServer: async (serverId) => {
    const response = await fetch(`${API_BASE_URL}/servers/${serverId}`, {
      method: 'DELETE'
    });
    return response.json();
  },
  
  // Activity
  getActivity: async (limit = 50) => {
    const response = await fetch(`${API_BASE_URL}/activity?limit=${limit}`);
    return response.json();
  },
  
  // Alerts
  getAlerts: async (filter = 'all') => {
    const response = await fetch(`${API_BASE_URL}/alerts?filter=${filter}`);
    return response.json();
  },
  
  // File Changes
  getFileChanges: async (serverId = null) => {
    const url = serverId ? `${API_BASE_URL}/files?server_id=${serverId}` : `${API_BASE_URL}/files`;
    const response = await fetch(url);
    return response.json();
  },
  
  // Permission Changes
  getPermissionChanges: async (serverId = null) => {
    const url = serverId ? `${API_BASE_URL}/permissions?server_id=${serverId}` : `${API_BASE_URL}/permissions`;
    const response = await fetch(url);
    return response.json();
  },
  
  // Backups
  getBackups: async () => {
    const response = await fetch(`${API_BASE_URL}/backups`);
    return response.json();
  },
  
  createBackup: async (serverId) => {
    const response = await fetch(`${API_BASE_URL}/backups`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ server_id: serverId })
    });
    return response.json();
  },
  
  restoreBackup: async (backupId) => {
    const response = await fetch(`${API_BASE_URL}/backups/${backupId}/restore`, {
      method: 'POST'
    });
    return response.json();
  },
  
  // Settings
  getAlertConfig: async () => {
    const response = await fetch(`${API_BASE_URL}/settings/alerts`);
    return response.json();
  },
  
  updateAlertConfig: async (config) => {
    const response = await fetch(`${API_BASE_URL}/settings/alerts`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });
    return response.json();
  },
  
  getGeneralSettings: async () => {
    const response = await fetch(`${API_BASE_URL}/settings/general`);
    return response.json();
  },
  
  updateGeneralSettings: async (settings) => {
    const response = await fetch(`${API_BASE_URL}/settings/general`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return response.json();
  }
};

const App = () => {
  const [activePage, setActivePage] = useState('dashboard');
  const [servers, setServers] = useState([]);
  const [stats, setStats] = useState({
    totalServers: 0,
    activeMonitors: 0,
    alertsToday: 0,
    restoredFiles: 0
  });
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [activityData, setActivityData] = useState([]);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      const [statsData, serversData, alertsData] = await Promise.all([
        api.getDashboardStats(),
        api.getServers(),
        api.getAlerts()
      ]);
      
      setStats(statsData);
      setServers(serversData);
      setRecentAlerts(alertsData.slice(0, 3));
      
      // Mock activity data for chart
      setActivityData([
        { name: 'Mon', fileChanges: 12, permChanges: 8, restores: 5 },
        { name: 'Tue', fileChanges: 19, permChanges: 12, restores: 8 },
        { name: 'Wed', fileChanges: 15, permChanges: 10, restores: 6 },
        { name: 'Thu', fileChanges: 25, permChanges: 15, restores: 10 },
        { name: 'Fri', fileChanges: 22, permChanges: 13, restores: 9 },
        { name: 'Sat', fileChanges: 18, permChanges: 11, restores: 7 },
        { name: 'Sun', fileChanges: 15, permChanges: 9, restores: 6 }
      ]);
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    }
  };

  const Sidebar = () => (
    <aside className="w-64 bg-gray-900 text-white fixed h-screen overflow-y-auto">
      <div className="p-5 bg-gray-800 border-b border-gray-700">
        <h1 className="text-xl font-bold flex items-center gap-3">
          <Shield className="w-8 h-8 text-blue-500" />
          Anti-Defacement
        </h1>
      </div>
      
      <nav className="py-5">
        <div className="mb-8">
          <div className="px-5 pb-3 text-xs uppercase text-gray-500 font-semibold">Main</div>
          <MenuItem icon={<Activity />} label="Dashboard" page="dashboard" active={activePage === 'dashboard'} onClick={setActivePage} />
          <MenuItem icon={<Server />} label="Servers" page="servers" active={activePage === 'servers'} onClick={setActivePage} />
          <MenuItem icon={<Eye />} label="Activity Log" page="activity" active={activePage === 'activity'} onClick={setActivePage} />
          <MenuItem icon={<Bell />} label="Alerts" page="alerts" active={activePage === 'alerts'} onClick={setActivePage} />
        </div>

        <div className="mb-8">
          <div className="px-5 pb-3 text-xs uppercase text-gray-500 font-semibold">Monitoring</div>
          <MenuItem icon={<FileText />} label="File Changes" page="files" active={activePage === 'files'} onClick={setActivePage} />
          <MenuItem icon={<Lock />} label="Permissions" page="permissions" active={activePage === 'permissions'} onClick={setActivePage} />
          <MenuItem icon={<HardDrive />} label="Backups" page="backups" active={activePage === 'backups'} onClick={setActivePage} />
        </div>

        <div>
          <div className="px-5 pb-3 text-xs uppercase text-gray-500 font-semibold">Settings</div>
          <MenuItem icon={<Settings />} label="Alert Config" page="alert-config" active={activePage === 'alert-config'} onClick={setActivePage} />
          <MenuItem icon={<Plus />} label="Add Server" page="add-server" active={activePage === 'add-server'} onClick={setActivePage} />
          <MenuItem icon={<Settings />} label="General Settings" page="settings" active={activePage === 'settings'} onClick={setActivePage} />
        </div>
      </nav>
    </aside>
  );

  const MenuItem = ({ icon, label, page, active, onClick }) => (
    <div
      onClick={() => onClick(page)}
      className={`px-5 py-3 flex items-center gap-3 cursor-pointer transition-all border-l-3 ${
        active 
          ? 'bg-blue-900 bg-opacity-20 text-blue-500 border-blue-500' 
          : 'text-gray-400 hover:bg-gray-800 border-transparent'
      }`}
    >
      <span className="w-5 h-5">{icon}</span>
      {label}
    </div>
  );

  const Topbar = () => (
    <div className="bg-white px-8 py-4 border-b border-gray-200 sticky top-0 z-10">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-semibold text-gray-800">
          {activePage.charAt(0).toUpperCase() + activePage.slice(1).replace('-', ' ')}
        </h2>
        <div className="flex gap-4 items-center">
          <div className="px-3 py-2 bg-green-100 text-green-800 rounded-lg flex items-center gap-2 text-sm font-semibold">
            <span className="w-2 h-2 bg-green-600 rounded-full animate-pulse"></span>
            All Systems Active
          </div>
          <button className="px-4 py-2 bg-blue-600 text-white rounded-lg flex items-center gap-2 text-sm font-semibold hover:bg-blue-700">
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>
    </div>
  );

  const StatCard = ({ title, value, change, icon, color }) => (
    <div className="bg-white p-6 rounded-xl shadow-sm hover:shadow-md transition-shadow">
      <div className="flex justify-between items-start mb-4">
        <span className="text-sm text-gray-600 font-medium">{title}</span>
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color}`}>
          {icon}
        </div>
      </div>
      <div className="text-3xl font-bold text-gray-800 mb-2">{value}</div>
      <div className={`text-sm ${change.includes('↑') ? 'text-green-600' : 'text-red-600'}`}>
        {change}
      </div>
    </div>
  );

  const DashboardPage = () => (
    <div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <StatCard 
          title="Total Servers" 
          value={stats.totalServers} 
          change="↑ 2 new this month"
          icon={<Server className="text-blue-600" />}
          color="bg-blue-100"
        />
        <StatCard 
          title="Active Monitors" 
          value={stats.activeMonitors} 
          change="↑ All online"
          icon={<Eye className="text-green-600" />}
          color="bg-green-100"
        />
        <StatCard 
          title="Alerts Today" 
          value={stats.alertsToday} 
          change="↓ 3 critical"
          icon={<Bell className="text-yellow-600" />}
          color="bg-yellow-100"
        />
        <StatCard 
          title="Restored Files" 
          value={stats.restoredFiles} 
          change="↓ 23% from yesterday"
          icon={<RefreshCw className="text-green-600" />}
          color="bg-green-100"
        />
      </div>

      <div className="bg-white rounded-xl shadow-sm p-6 mb-6">
        <h3 className="text-lg font-semibold mb-4">Activity Overview (Last 7 Days)</h3>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={activityData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Line type="monotone" dataKey="fileChanges" stroke="#2563eb" strokeWidth={2} name="File Changes" />
            <Line type="monotone" dataKey="permChanges" stroke="#f59e0b" strokeWidth={2} name="Permission Changes" />
            <Line type="monotone" dataKey="restores" stroke="#10b981" strokeWidth={2} name="Restores" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white rounded-xl shadow-sm p-6">
          <h3 className="text-lg font-semibold mb-4">Recent Alerts</h3>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Time</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Server</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Type</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Action</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map((alert, idx) => (
                  <tr key={idx} className="border-b hover:bg-gray-50">
                    <td className="px-4 py-4 text-sm">{alert.time}</td>
                    <td className="px-4 py-4 text-sm">{alert.server}</td>
                    <td className="px-4 py-4 text-sm">{alert.type}</td>
                    <td className="px-4 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${
                        alert.severity === 'critical' ? 'bg-red-100 text-red-800' :
                        alert.severity === 'warning' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-blue-100 text-blue-800'
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <button className="px-3 py-1 bg-blue-600 text-white rounded text-xs font-semibold hover:bg-blue-700">
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6">
          <h3 className="text-lg font-semibold mb-4">Quick Actions</h3>
          <div className="flex flex-col gap-3">
            <button className="px-4 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 flex items-center justify-center gap-2">
              <Plus className="w-4 h-4" />
              Add New Server
            </button>
            <button className="px-4 py-3 bg-green-600 text-white rounded-lg font-semibold hover:bg-green-700 flex items-center justify-center gap-2">
              <RefreshCw className="w-4 h-4" />
              Force Restore All
            </button>
            <button className="px-4 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 flex items-center justify-center gap-2">
              <Settings className="w-4 h-4" />
              Test Alerts
            </button>
            <button className="px-4 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 flex items-center justify-center gap-2">
              <Activity className="w-4 h-4" />
              Generate Report
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  const ServersPage = () => (
    <div className="bg-white rounded-xl shadow-sm p-6">
      <div className="flex justify-between items-center mb-6">
        <h3 className="text-lg font-semibold">Monitored Servers</h3>
        <button 
          onClick={() => setActivePage('add-server')}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 flex items-center gap-2"
        >
          <Plus className="w-4 h-4" />
          Add Server
        </button>
      </div>
      <div className="space-y-4">
        {servers.map((server, idx) => (
          <div key={idx} className="border-2 border-gray-200 rounded-lg p-5 hover:border-blue-500 transition-all flex justify-between items-center">
            <div className="flex gap-4 items-center">
              <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-blue-500 to-green-500 flex items-center justify-center text-white font-bold text-lg">
                {server.name.substring(0, 2).toUpperCase()}
              </div>
              <div>
                <h4 className="font-semibold text-lg">{server.name}</h4>
                <p className="text-sm text-gray-600">{server.ip} • {server.path}</p>
              </div>
            </div>
            <div className="flex gap-6 items-center">
              <div className="text-center">
                <div className="text-xl font-bold text-green-600">✓</div>
                <div className="text-xs text-gray-600 uppercase">Status</div>
              </div>
              <div className="text-center">
                <div className="text-xl font-bold">{server.changes}</div>
                <div className="text-xs text-gray-600 uppercase">Changes</div>
              </div>
              <div className="text-center">
                <div className="text-xl font-bold">{server.alerts}</div>
                <div className="text-xs text-gray-600 uppercase">Alerts</div>
              </div>
              <button className="px-3 py-2 bg-red-600 text-white rounded-lg text-sm font-semibold hover:bg-red-700">
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':
        return <DashboardPage />;
      case 'servers':
        return <ServersPage />;
      default:
        return <DashboardPage />;
    }
  };

  return (
    <div className="flex min-h-screen bg-gray-100">
      <Sidebar />
      <main className="ml-64 flex-1">
        <Topbar />
        <div className="p-8">
          {renderPage()}
        </div>
      </main>
    </div>
  );
};

export default App;