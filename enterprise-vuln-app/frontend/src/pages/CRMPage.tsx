import React from 'react'
import { motion } from 'framer-motion'

const CRMPage: React.FC = () => {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <h1 className="text-2xl font-bold text-white mb-4">Customer Relationship Management</h1>
      <div className="enterprise-card">
        <p className="text-gray-400">CRM interface coming soon...</p>
      </div>
    </motion.div>
  )
}

export default CRMPage

