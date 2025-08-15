import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Plus, Target, Globe, Shield, Trash2, Edit, Eye } from 'lucide-react';
import { useAppContext } from '../context/AppContext';
import { useTargets, useDeleteTarget } from '../hooks/useApi';
import AddTargetModal from '../components/AddTargetModal';

const Targets: React.FC = () => {
  const { state } = useAppContext();
  const targetsQuery = useTargets();
  const deleteTargetMutation = useDeleteTarget();
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [selectedTargetId, setSelectedTargetId] = useState<string | null>(null);

  // Ensure data is loaded
  React.useEffect(() => {
    if (targetsQuery.refetch) {
      targetsQuery.refetch();
    }
  }, []);

  const handleDeleteTarget = async (id: string, name: string) => {
    if (window.confirm(`Are you sure you want to delete "${name}"? This action cannot be undone.`)) {
      try {
        await deleteTargetMutation.mutateAsync(id);
      } catch (error) {
        // Error handling is done in the mutation
      }
    }
  };

  if (targetsQuery.isLoading) {
    return (
      <div className="min-h-screen bg-cyber-black text-cyber-white p-6 flex items-center justify-center">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
          className="w-8 h-8 border-2 border-neon-cyan border-t-transparent rounded-full"
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-cyber-black text-cyber-white p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-glow mb-2">
              TARGET ACQUISITION
            </h1>
            <p className="text-cyber-muted">
              Manage reconnaissance targets and attack surfaces
            </p>
          </div>
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setIsAddModalOpen(true)}
            className="bg-neon-cyan bg-opacity-20 border border-neon-cyan text-neon-cyan px-6 py-3 rounded-lg flex items-center gap-2 hover:bg-opacity-30 transition-all"
          >
            <Plus size={20} />
            ADD TARGET
          </motion.button>
        </div>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {[
          { label: 'Active Targets', value: state.stats.totalTargets.toString(), icon: Target, color: 'neon-cyan' },
          { label: 'Total Domains', value: state.targets.length.toString(), icon: Globe, color: 'neon-pink' },
          { label: 'Protected Assets', value: state.targets.filter(t => t.is_active).length.toString(), icon: Shield, color: 'neon-green' },
          { label: 'High Priority', value: '0', icon: Eye, color: 'neon-orange' }
        ].map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6 hover:border-opacity-50 transition-all"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-cyber-muted text-sm">{stat.label}</p>
                <p className={`text-2xl font-bold text-${stat.color}`}>
                  {stat.value}
                </p>
              </div>
              <stat.icon className={`text-${stat.color}`} size={24} />
            </div>
          </motion.div>
        ))}
      </div>

      {/* Targets Table */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
        className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg overflow-hidden"
      >
        <div className="p-6 border-b border-cyber-gray border-opacity-30">
          <h2 className="text-xl font-bold text-neon-cyan">ACTIVE TARGETS</h2>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-cyber-gray bg-opacity-5">
              <tr>
                <th className="text-left p-4 text-cyber-muted">Target Name</th>
                <th className="text-left p-4 text-cyber-muted">Domain</th>
                <th className="text-left p-4 text-cyber-muted">Scope</th>
                <th className="text-left p-4 text-cyber-muted">Status</th>
                <th className="text-left p-4 text-cyber-muted">Last Scan</th>
                <th className="text-left p-4 text-cyber-muted">Vulnerabilities</th>
                <th className="text-left p-4 text-cyber-muted">Actions</th>
              </tr>
            </thead>
            <tbody>
              {state.targets.map((target, index) => (
                <motion.tr
                  key={target.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.5 + index * 0.1 }}
                  className="border-b border-cyber-gray border-opacity-20 hover:bg-cyber-gray hover:bg-opacity-5"
                >
                  <td className="p-4">
                    <div className="font-medium text-cyber-white">{target.name}</div>
                  </td>
                  <td className="p-4">
                    <div className="text-neon-cyan font-mono">{target.domain}</div>
                  </td>
                  <td className="p-4">
                    <div className="text-cyber-muted">{target.scope}</div>
                  </td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded text-xs font-bold ${
                      target.is_active 
                        ? 'bg-neon-green bg-opacity-20 text-neon-green' 
                        : 'bg-cyber-gray bg-opacity-20 text-cyber-gray'
                    }`}>
                      {target.is_active ? 'ACTIVE' : 'INACTIVE'}
                    </span>
                  </td>
                                      <td className="p-4">
                      <div className="text-cyber-muted text-sm">
                        {new Date(target.updated_at).toLocaleDateString()}
                      </div>
                    </td>
                    <td className="p-4">
                      <span className="text-cyber-muted text-sm">
                        -
                      </span>
                    </td>
                                      <td className="p-4">
                      <div className="flex gap-2">
                        <button 
                          onClick={() => setSelectedTargetId(target.id)}
                          className="text-neon-cyan hover:text-cyber-white transition-colors"
                          title="View Details"
                        >
                          <Eye size={16} />
                        </button>
                        <button 
                          className="text-neon-green hover:text-cyber-white transition-colors"
                          title="Edit Target"
                        >
                          <Edit size={16} />
                        </button>
                        <button 
                          onClick={() => handleDeleteTarget(target.id, target.name)}
                          disabled={deleteTargetMutation.isLoading}
                          className="text-neon-orange hover:text-cyber-white transition-colors disabled:opacity-50"
                          title="Delete Target"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* Add Target Modal */}
      <AddTargetModal 
        isOpen={isAddModalOpen} 
        onClose={() => setIsAddModalOpen(false)} 
      />
    </div>
  );
};

export default Targets; 