import React from 'react'
import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Tasks from './pages/Tasks'
import NewTask from './pages/NewTask'
import TaskDetail from './pages/TaskDetail'
import Vulnerabilities from './pages/Vulnerabilities'
import Reports from './pages/Reports'
import Recon from './pages/Recon'
import Attack from './pages/Attack'
import POCManagement from './pages/POCManagement'
import PacketVerifier from './pages/PacketVerifier'
import Settings from './pages/Settings'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/tasks" element={<Tasks />} />
        <Route path="/tasks/new" element={<NewTask />} />
        <Route path="/tasks/:taskId" element={<TaskDetail />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/recon" element={<Recon />} />
        <Route path="/attack" element={<Attack />} />
        <Route path="/pocs" element={<POCManagement />} />
        <Route path="/verify" element={<PacketVerifier />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
    </Routes>
  )
}
