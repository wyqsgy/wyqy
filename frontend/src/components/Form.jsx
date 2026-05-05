import React, { useState, useCallback } from 'react'

const VALIDATORS = {
  required: (v) => (!v || v.trim() === '' ? '此项为必填' : null),
  url: (v) => {
    if (!v) return null
    try {
      new URL(v)
      return null
    } catch {
      return '请输入有效的URL地址'
    }
  },
  ip: (v) => {
    if (!v) return null
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
    if (!ipRegex.test(v)) return '请输入有效的IP地址'
    const parts = v.split('/')[0].split('.')
    if (parts.some(p => parseInt(p) > 255)) return 'IP地址超出范围'
    return null
  },
  minLength: (min) => (v) => {
    if (!v || v.length < min) return `至少需要 ${min} 个字符`
    return null
  },
  maxLength: (max) => (v) => {
    if (v && v.length > max) return `不能超过 ${max} 个字符`
    return null
  },
  email: (v) => {
    if (!v) return null
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(v) ? null : '请输入有效的邮箱地址'
  },
  number: (v) => {
    if (!v) return null
    return isNaN(Number(v)) ? '请输入有效的数字' : null
  },
  port: (v) => {
    if (!v) return null
    const port = parseInt(v)
    if (isNaN(port) || port < 1 || port > 65535) return '端口范围: 1-65535'
    return null
  },
}

export function useForm({ initialValues = {}, onSubmit }) {
  const [values, setValues] = useState(initialValues)
  const [errors, setErrors] = useState({})
  const [touched, setTouched] = useState({})
  const [submitting, setSubmitting] = useState(false)

  const setValue = useCallback((name, value) => {
    setValues(prev => ({ ...prev, [name]: value }))
    setErrors(prev => {
      const next = { ...prev }
      delete next[name]
      return next
    })
  }, [])

  const setFieldTouched = useCallback((name) => {
    setTouched(prev => ({ ...prev, [name]: true }))
  }, [])

  const validateField = useCallback((name, value, rules = []) => {
    for (const rule of rules) {
      let validator
      if (typeof rule === 'string') {
        validator = VALIDATORS[rule]
      } else if (typeof rule === 'function') {
        validator = rule
      } else if (typeof rule === 'object' && rule.name) {
        const fn = VALIDATORS[rule.name]
        validator = fn ? fn(rule.value) : null
      }
      if (validator) {
        const error = validator(value)
        if (error) return error
      }
    }
    return null
  }, [])

  const validateAll = useCallback((fieldRules = {}) => {
    const newErrors = {}
    for (const [name, rules] of Object.entries(fieldRules)) {
      const error = validateField(name, values[name] || '', rules)
      if (error) newErrors[name] = error
    }
    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }, [values, validateField])

  const handleSubmit = useCallback(async (e, fieldRules = {}) => {
    e?.preventDefault()
    const allTouched = {}
    Object.keys(fieldRules).forEach(k => { allTouched[k] = true })
    setTouched(allTouched)

    if (!validateAll(fieldRules)) return

    setSubmitting(true)
    try {
      await onSubmit(values)
    } catch (err) {
      setErrors(prev => ({ ...prev, _form: err.message || '提交失败' }))
    } finally {
      setSubmitting(false)
    }
  }, [values, validateAll, onSubmit])

  const reset = useCallback(() => {
    setValues(initialValues)
    setErrors({})
    setTouched({})
    setSubmitting(false)
  }, [initialValues])

  return {
    values,
    errors,
    touched,
    submitting,
    setValue,
    setFieldTouched,
    validateField,
    validateAll,
    handleSubmit,
    reset,
  }
}

export function FormField({
  label,
  name,
  type = 'text',
  value,
  error,
  touched,
  onChange,
  onBlur,
  placeholder,
  required,
  disabled,
  helpText,
  options,
  rows,
  style = {},
  className = '',
}) {
  const hasError = touched && error
  const inputId = `field-${name}`

  const baseInputStyle = {
    fontFamily: 'var(--font-body)',
    fontSize: '14px',
    padding: '10px 14px',
    border: `1px solid ${hasError ? 'var(--danger)' : 'var(--border-color)'}`,
    borderRadius: '6px',
    background: 'var(--bg-primary)',
    color: 'var(--text-primary)',
    outline: 'none',
    transition: 'border-color 0.15s ease, box-shadow 0.15s ease',
    width: '100%',
    boxShadow: hasError ? '0 0 0 2px var(--danger-subtle)' : 'none',
  }

  const renderInput = () => {
    switch (type) {
      case 'textarea':
        return (
          <textarea
            id={inputId}
            name={name}
            value={value || ''}
            onChange={(e) => onChange(name, e.target.value)}
            onBlur={() => onBlur(name)}
            placeholder={placeholder}
            disabled={disabled}
            rows={rows || 4}
            style={baseInputStyle}
            className="focus-ring"
          />
        )
      case 'select':
        return (
          <select
            id={inputId}
            name={name}
            value={value || ''}
            onChange={(e) => onChange(name, e.target.value)}
            onBlur={() => onBlur(name)}
            disabled={disabled}
            style={baseInputStyle}
            className="focus-ring"
          >
            {placeholder && <option value="">{placeholder}</option>}
            {(options || []).map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        )
      case 'checkbox':
        return (
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              id={inputId}
              name={name}
              checked={!!value}
              onChange={(e) => onChange(name, e.target.checked)}
              disabled={disabled}
              style={{ width: '16px', height: '16px', accentColor: 'var(--accent)' }}
            />
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{label}</span>
          </label>
        )
      default:
        return (
          <input
            id={inputId}
            type={type}
            name={name}
            value={value || ''}
            onChange={(e) => onChange(name, e.target.value)}
            onBlur={() => onBlur(name)}
            placeholder={placeholder}
            disabled={disabled}
            style={baseInputStyle}
            className="focus-ring"
            autoComplete="off"
          />
        )
    }
  }

  return (
    <div className={className} style={{ marginBottom: '16px', ...style }}>
      {type !== 'checkbox' && label && (
        <label
          htmlFor={inputId}
          style={{
            display: 'block',
            fontSize: '12px',
            fontWeight: 600,
            color: 'var(--text-secondary)',
            marginBottom: '6px',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
          }}
        >
          {label}
          {required && <span style={{ color: 'var(--danger)', marginLeft: '4px' }}>*</span>}
        </label>
      )}
      {renderInput()}
      {hasError && (
        <div style={{
          fontSize: '11px',
          color: 'var(--danger)',
          marginTop: '4px',
          display: 'flex',
          alignItems: 'center',
          gap: '4px',
        }}>
          <span>!</span>
          {error}
        </div>
      )}
      {helpText && !hasError && (
        <div style={{
          fontSize: '11px',
          color: 'var(--text-dim)',
          marginTop: '4px',
        }}>
          {helpText}
        </div>
      )}
    </div>
  )
}

export { VALIDATORS }
