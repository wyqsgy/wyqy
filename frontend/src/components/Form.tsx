import React, { forwardRef } from 'react'

interface FormProps extends React.FormHTMLAttributes<HTMLFormElement> {
  children: React.ReactNode
}

export const Form = forwardRef<HTMLFormElement, FormProps>(
  ({ children, className = '', ...props }, ref) => {
    return (
      <form ref={ref} className={`space-y-4 ${className}`} {...props}>
        {children}
      </form>
    )
  }
)

Form.displayName = 'Form'

interface FormFieldProps {
  label?: string
  error?: string
  hint?: string
  children: React.ReactNode
  className?: string
}

export function FormField({ label, error, hint, children, className = '' }: FormFieldProps) {
  return (
    <div className={`space-y-1 ${className}`}>
      {label && <label className="label-text block">{label}</label>}
      {children}
      {hint && !error && <p className="text-xs text-[var(--text-dim)]">{hint}</p>}
      {error && <p className="text-xs text-[var(--danger)]">{error}</p>}
    </div>
  )
}

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  error?: boolean
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ error, className = '', ...props }, ref) => {
    return (
      <input
        ref={ref}
        className={`input-field ${error ? 'border-[var(--danger)]' : ''} ${className}`}
        {...props}
      />
    )
  }
)

Input.displayName = 'Input'

interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  error?: boolean
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ error, className = '', ...props }, ref) => {
    return (
      <textarea
        ref={ref}
        className={`input-field resize-none ${error ? 'border-[var(--danger)]' : ''} ${className}`}
        {...props}
      />
    )
  }
)

Textarea.displayName = 'Textarea'

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  error?: boolean
  options: { value: string; label: string }[]
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ error, options, className = '', ...props }, ref) => {
    return (
      <select
        ref={ref}
        className={`pixel-select ${error ? 'border-[var(--danger)]' : ''} ${className}`}
        {...props}
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    )
  }
)

Select.displayName = 'Select'
