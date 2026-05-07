import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useCreateTask } from '../hooks/useTasks'
import { useToast } from '../contexts/ToastContext'
import { Form, FormField, Input, Select } from '../components/Form'

const scanTypes = [
  { value: 'full', label: 'Full Scan' },
  { value: 'quick', label: 'Quick Scan' },
  { value: 'recon', label: 'Reconnaissance' },
  { value: 'deep', label: 'Deep Scan' },
]

export default function NewTask() {
  const navigate = useNavigate()
  const createTask = useCreateTask()
  const { addToast } = useToast()
  const [formData, setFormData] = useState({
    name: '',
    target: '',
    scan_type: 'quick',
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const task = await createTask.mutateAsync(formData)
      addToast({ type: 'success', message: 'Task created successfully' })
      navigate(`/tasks/${task.id}`)
    } catch {
      addToast({ type: 'error', message: 'Failed to create task' })
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6 page-enter">
      <h1 className="sec-title text-2xl">Create New Task</h1>

      <Form onSubmit={handleSubmit}>
        <FormField label="Task Name">
          <Input
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="My Security Scan"
            required
          />
        </FormField>

        <FormField label="Target URL">
          <Input
            value={formData.target}
            onChange={(e) => setFormData({ ...formData, target: e.target.value })}
            placeholder="https://example.com"
            required
          />
        </FormField>

        <FormField label="Scan Type">
          <Select
            value={formData.scan_type}
            onChange={(e) => setFormData({ ...formData, scan_type: e.target.value })}
            options={scanTypes}
          />
        </FormField>

        <div className="flex gap-4 pt-4">
          <button type="submit" className="btn btn-accent" disabled={createTask.isPending}>
            {createTask.isPending ? 'Creating...' : 'Create Task'}
          </button>
          <button type="button" className="btn" onClick={() => navigate('/tasks')}>
            Cancel
          </button>
        </div>
      </Form>
    </div>
  )
}
