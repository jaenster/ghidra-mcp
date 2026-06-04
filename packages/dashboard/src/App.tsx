import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import { Overview } from './pages/Overview';
import { Workers } from './pages/Workers';
import { Commands } from './pages/Commands';
import { Logs } from './pages/Logs';

const navStyle = {
  display: 'flex',
  gap: 16,
  padding: '12px 24px',
  background: '#0d0d1a',
  borderBottom: '1px solid #333',
} as const;

const linkStyle = (isActive: boolean) => ({
  color: isActive ? '#3b82f6' : '#888',
  textDecoration: 'none',
  fontWeight: isActive ? 700 : 400,
  fontSize: 14,
});

export function App() {
  return (
    <BrowserRouter basename="/dashboard">
      <div style={{ color: '#ddd', background: '#111', minHeight: '100vh', fontFamily: 'system-ui, sans-serif' }}>
        <nav style={navStyle}>
          <span style={{ fontWeight: 700, color: '#fff', marginRight: 16 }}>Ghidra MCP</span>
          <NavLink to="/" end style={({ isActive }) => linkStyle(isActive)}>Overview</NavLink>
          <NavLink to="/workers" style={({ isActive }) => linkStyle(isActive)}>Workers</NavLink>
          <NavLink to="/commands" style={({ isActive }) => linkStyle(isActive)}>Commands</NavLink>
          <NavLink to="/logs" style={({ isActive }) => linkStyle(isActive)}>Logs</NavLink>
        </nav>
        <main style={{ padding: 24 }}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/workers" element={<Workers />} />
            <Route path="/commands" element={<Commands />} />
            <Route path="/logs" element={<Logs />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
