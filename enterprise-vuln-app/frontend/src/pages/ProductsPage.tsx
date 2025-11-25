import React from 'react'
import { motion } from 'framer-motion'

const ProductsPage: React.FC = () => {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <h1 className="text-2xl font-bold text-white mb-4">Product Management</h1>
      <div className="enterprise-card">
        <p className="text-gray-400">Product management interface coming soon...</p>
      </div>
    </motion.div>
  )
}

export default ProductsPage

