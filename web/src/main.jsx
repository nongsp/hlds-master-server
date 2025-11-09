import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import io from 'socket.io-client';
import './index.css';

const API_BASE = '/api';
const WS_URL = '/ws';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(null);
  const [servers, setServers] = useState([]);
  const [stats, setStats] = useState({ total_servers: 0, total_players: 0, games: {} });
  const [filter, setFilter] = useState({ gamedir: '', map: '' });

  useEffect(() => {
    if (token) {
      fetchServers();
      const socket = io(WS_URL, { transports: ['websocket'] });
      socket.on('stats', setStats);
      return () => socket.close();
    }
  }, [token, filter]);

  const fetchServers = async () => {
    const params = new URLSearchParams();
    if (filter.gamedir) params.append('gamedir', filter.gamedir);
    if (filter.map) params.append('map', filter.map);
    const res = await fetch(`${API_BASE}/servers?${params}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (res.ok) setServers(await res.json());
  };

  const login = async (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    const res = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      body: new URLSearchParams(form)
    });
    if (res.ok) {
      const { access_token } = await res.json();
      localStorage.setItem('token', access_token);
      setToken(access_token);
    }
  };

  if (!token) {
    return (
      <div className="flex items-center justify-center h-screen">
        <form onSubmit={login} className="bg-gray-800 p-8 rounded w-96">
          <h2 className="text-2xl mb-6 text-center">HLDS Master Login</h2>
          <input name="username" placeholder="Username" defaultValue="admin" className="block w-full mb-3 p-2 bg-gray-700 rounded" />
          <input name="password" type="password" placeholder="Password" defaultValue="admin123" className="block w-full mb-4 p-2 bg-gray-700 rounded" />
          <button type="submit" className="w-full bg-blue-600 p-2 rounded hover:bg-blue-700">Login</button>
        </form>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">HLDS Master Panel</h1>
        <button onClick={() => { localStorage.removeItem('token'); setToken(null); }} className="bg-red-600 px-4 py-2 rounded">Logout</button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-blue-900 p-4 rounded"><h3>Servers</h3><p className="text-2xl">{stats.total_servers}</p></div>
        <div className="bg-green-900 p-4 rounded"><h3>Players</h3><p className="text-2xl">{stats.total_players}</p></div>
        <div className="bg-purple-900 p-4 rounded"><h3>Games</h3><p className="text-xl">{Object.keys(stats.games).length}</p></div>
      </div>

      <div className="flex gap-2 mb-4">
        <input placeholder="Filter gamedir..." className="bg-gray-800 px-3 py-1 rounded" onChange={e => setFilter({ ...filter, gamedir: e.target.value })} />
        <input placeholder="Filter map..." className="bg-gray-800 px-3 py-1 rounded" onChange={e => setFilter({ ...filter, map: e.target.value })} />
      </div>

      <div className="space-y-2">
        {servers.map(s => (
          <div key={`${s.ip}:${s.port}`} className="bg-gray-800 p-3 rounded flex justify-between items-center">
            <div>
              <strong>{s.gamedir}</strong> | {s.map} | {s.ip}:{s.port}
            </div>
            <div>
              {s.players}/{s.max_players} {s.password && '[P]'} {s.secure && '[VAC]'}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
