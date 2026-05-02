import React from 'react'
import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import TaskList from './pages/TaskList'
import NewTask from './pages/NewTask'
import TaskDetail from './pages/TaskDetail'
import Vulnerabilities from './pages/Vulnerabilities'
import Reports from './pages/Reports'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/tasks" element={<TaskList />} />
        <Route path="/tasks/new" element={<NewTask />} />
        <Route path="/tasks/:taskId" element={<TaskDetail />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/reports" element={<Reports />} />
      </Route>
    </Routes>
  )
}
