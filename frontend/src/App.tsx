import React, { Suspense, lazy } from 'react'
import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import LoadingFallback from './components/LoadingFallback'
import ErrorBoundary from './components/ErrorBoundary'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const Tasks = lazy(() => import('./pages/Tasks'))
const NewTask = lazy(() => import('./pages/NewTask'))
const TaskDetail = lazy(() => import('./pages/TaskDetail'))
const Vulnerabilities = lazy(() => import('./pages/Vulnerabilities'))
const Reports = lazy(() => import('./pages/Reports'))
const Recon = lazy(() => import('./pages/Recon'))
const Attack = lazy(() => import('./pages/Attack'))
const POCManagement = lazy(() => import('./pages/POCManagement'))
const PacketVerifier = lazy(() => import('./pages/PacketVerifier'))
const Templates = lazy(() => import('./pages/Templates'))
const Settings = lazy(() => import('./pages/Settings'))

function LazyPage({ children }: { children: React.ReactNode }) {
  return (
    <ErrorBoundary>
      <Suspense fallback={<LoadingFallback />}>
        {children}
      </Suspense>
    </ErrorBoundary>
  )
}

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<LazyPage><Dashboard /></LazyPage>} />
        <Route path="/tasks" element={<LazyPage><Tasks /></LazyPage>} />
        <Route path="/tasks/new" element={<LazyPage><NewTask /></LazyPage>} />
        <Route path="/tasks/:taskId" element={<LazyPage><TaskDetail /></LazyPage>} />
        <Route path="/vulnerabilities" element={<LazyPage><Vulnerabilities /></LazyPage>} />
        <Route path="/reports" element={<LazyPage><Reports /></LazyPage>} />
        <Route path="/recon" element={<LazyPage><Recon /></LazyPage>} />
        <Route path="/attack" element={<LazyPage><Attack /></LazyPage>} />
        <Route path="/pocs" element={<LazyPage><POCManagement /></LazyPage>} />
        <Route path="/verify" element={<LazyPage><PacketVerifier /></LazyPage>} />
        <Route path="/templates" element={<LazyPage><Templates /></LazyPage>} />
        <Route path="/settings" element={<LazyPage><Settings /></LazyPage>} />
      </Route>
    </Routes>
  )
}
