import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Plus, Target, Globe, Shield, Trash2, Edit, Eye, X } from 'lucide-react';
import { useAppContext } from '../context/AppContext';
import { useTargets, useDeleteTarget, useUpdateTarget } from '../hooks/useApi';
import AddTargetModal from '../components/AddTargetModal';

const Targets: React.FC = () => {
  const { state } = useAppContext();
  const targetsQuery = useTargets();
  const deleteTargetMutation = useDeleteTarget();
  const updateTargetMutation = useUpdateTarget();
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [selectedTargetId, setSelectedTargetId] = useState<string | null>(null);
  const [editingTarget, setEditingTarget] = useState<any>(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [showInactive, setShowInactive] = useState(false);

  // Ensure data is loaded
  React.useEffect(() => {
    if (targetsQuery.refetch) {
      targetsQuery.refetch();
    }
  }, []);

  // Derived list (hide inactive by default)
  const filteredTargets = state.targets.filter(t => showInactive || t.is_active);

  const handleDeleteTarget = async (idOrFlag: string, confirmMessage: string) => {
    if (window.confirm(confirmMessage)) {
      try {
        await deleteTargetMutation.mutateAsync(idOrFlag);
      } catch (error) {
        // Error handling is done in the mutation
      }
    }
  };

  const handleEditTarget = (target: any) => {
    setEditingTarget(target);
  };

  const handleUpdateTarget = async (formData: any) => {
    if (!editingTarget) return;
    
    try {
      await updateTargetMutation.mutateAsync({
        id: editingTarget.id,
        data: formData
      });
      setEditingTarget(null);
    } catch (error) {
      // Error handling is done in the mutation
    }
  };

  const handleViewDetails = (targetId: string) => {
    setSelectedTargetId(targetId);
    setShowDetailsModal(true);
  };

  const selectedTarget = state.targets.find(t => t.id === selectedTargetId);

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
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 pr-3 border-r border-cyber-gray/30">
              <span className="text-sm text-cyber-muted">Show Inactive</span>
              <button
                onClick={() => setShowInactive(v => !v)}
                className={`w-12 h-6 rounded-full transition-all ${
                  showInactive ? 'bg-neon-green' : 'bg-cyber-gray bg-opacity-50'
                }`}
                title="Toggle to include inactive targets in the list"
              >
                <div className={`w-5 h-5 bg-white rounded-full transition-transform ${
                  showInactive ? 'translate-x-6' : 'translate-x-0.5'
                }`} />
              </button>
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
        </div>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {[
          { label: 'Active Targets', value: state.stats.totalTargets.toString(), icon: Target, color: 'neon-cyan' },
          { label: 'Total Domains', value: state.targets.length.toString(), icon: Globe, color: 'neon-pink' },
          { label: 'Inactive Targets', value: state.targets.filter(t => !t.is_active).length.toString(), icon: Shield, color: 'neon-green' },
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
          <h2 className="text-xl font-bold text-neon-cyan">{showInactive ? 'ALL TARGETS' : 'ACTIVE TARGETS'}</h2>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-cyber-gray bg-opacity-5">
              <tr>
                <th className="text-left p-4 text-cyber-muted">Target Name</th>
                <th className="text-left p-4 text-cyber-muted">Domain</th>
                <th className="text-left p-4 text-cyber-muted w-64 md:w-80">Scope</th>
                <th className="text-left p-4 text-cyber-muted">Status</th>
                <th className="text-left p-4 text-cyber-muted hidden sm:table-cell">Last Scan</th>
                <th className="text-left p-4 text-cyber-muted hidden lg:table-cell">Vulnerabilities</th>
                <th className="text-left p-4 text-cyber-muted">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredTargets.map((target, index) => (
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
                    <div className="text-neon-cyan font-mono break-words">{target.domain}</div>
                  </td>
                  <td className="p-4">
                    <div className="text-cyber-muted whitespace-normal break-words max-w-[16rem] md:max-w-[20rem]">
                      {Array.isArray(target.scope) ? (
                        <div className="flex flex-wrap gap-1">
                          {target.scope.slice(0, 3).map((item: string, i: number) => (
                            <span key={i} className="inline-block bg-neon-green/10 text-neon-green px-2 py-0.5 rounded text-xs">
                              {item}
                            </span>
                          ))}
                          {target.scope.length > 3 && (
                            <span className="text-cyber-gray text-xs">+{target.scope.length - 3} more</span>
                          )}
                        </div>
                      ) : (
                        (() => {
                          const text = String(target.scope || '');
                          return text.length > 120 ? text.slice(0, 120) + '…' : text;
                        })()
                      )}
                    </div>
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
                  <td className="p-4 hidden sm:table-cell">
                    <div className="text-cyber-muted text-sm">
                      {new Date(target.updated_at).toLocaleDateString()}
                    </div>
                  </td>
                  <td className="p-4 hidden lg:table-cell">
                    <span className="text-cyber-muted text-sm">
                      -
                    </span>
                  </td>
                  <td className="p-4">
                    <div className="flex gap-2">
                      <button 
                        onClick={() => handleViewDetails(target.id)}
                        className="text-neon-cyan hover:text-cyber-white transition-colors"
                        title="View Details"
                      >
                        <Eye size={16} />
                      </button>
                      <button 
                        onClick={() => handleEditTarget(target)}
                        className="text-neon-green hover:text-cyber-white transition-colors"
                        title="Edit Target"
                      >
                        <Edit size={16} />
                      </button>
                      <button 
                        onClick={(e) => {
                          const isPermanent = e.shiftKey || e.metaKey || e.ctrlKey;
                          const idWithFlag = isPermanent ? `${target.id}::permanent` : target.id;
                          const msg = isPermanent
                            ? `Permanently delete "${target.name}" and all related scans?`
                            : `Deactivate "${target.name}"?`;
                          handleDeleteTarget(idWithFlag, msg);
                        }}
                        disabled={deleteTargetMutation.isLoading}
                        className="text-neon-orange hover:text-cyber-white transition-colors disabled:opacity-50"
                        title="Delete Target (hold Shift/Ctrl/Cmd for permanent)"
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

      {/* Edit Target Modal */}
      {editingTarget && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-cyber-dark rounded-lg border border-primary/30 w-full max-w-md"
          >
            <div className="p-6 border-b border-primary/30">
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-cyber text-primary">Edit Target</h3>
                <button
                  onClick={() => setEditingTarget(null)}
                  className="text-cyber-light hover:text-cyber-white"
                >
                  <X size={20} />
                </button>
              </div>
            </div>
            
            <form 
              onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.target as HTMLFormElement);
                handleUpdateTarget({
                  name: formData.get('name'),
                  description: formData.get('description'),
                  is_active: formData.get('is_active') === 'on'
                });
              }}
              className="p-6 space-y-4"
            >
              <div>
                <label className="block text-sm font-medium text-cyber-light mb-2">
                  Target Name
                </label>
                <input
                  type="text"
                  name="name"
                  defaultValue={editingTarget.name}
                  className="w-full px-3 py-2 bg-cyber-black border border-primary/30 rounded-md text-cyber-white focus:outline-none focus:border-primary"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-cyber-light mb-2">
                  Description
                </label>
                <textarea
                  name="description"
                  defaultValue={editingTarget.description || ''}
                  rows={3}
                  className="w-full px-3 py-2 bg-cyber-black border border-primary/30 rounded-md text-cyber-white focus:outline-none focus:border-primary"
                />
              </div>
              
              <div className="flex items-center">
                <input
                  type="checkbox"
                  name="is_active"
                  defaultChecked={editingTarget.is_active}
                  className="mr-2"
                />
                <label className="text-sm text-cyber-light">Active Target</label>
              </div>
              
              <div className="flex gap-3 pt-4">
                <button
                  type="submit"
                  disabled={updateTargetMutation.isLoading}
                  className="flex-1 bg-primary hover:bg-primary/80 text-cyber-black font-medium py-2 px-4 rounded-md transition-colors disabled:opacity-50"
                >
                  {updateTargetMutation.isLoading ? 'Updating...' : 'Update Target'}
                </button>
                <button
                  type="button"
                  onClick={() => setEditingTarget(null)}
                  className="flex-1 bg-cyber-light/20 hover:bg-cyber-light/30 text-cyber-white py-2 px-4 rounded-md transition-colors"
                >
                  Cancel
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}

      {/* Target Details Modal */}
      {showDetailsModal && selectedTarget && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-cyber-dark rounded-lg border border-primary/30 w-full max-w-2xl max-h-[80vh] overflow-y-auto"
          >
            <div className="p-6 border-b border-primary/30">
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-cyber text-primary">Target Details</h3>
                <button
                  onClick={() => setShowDetailsModal(false)}
                  className="text-cyber-light hover:text-cyber-white"
                >
                  <X size={20} />
                </button>
              </div>
            </div>
            
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="text-sm font-medium text-cyber-light mb-1">Name</h4>
                  <p className="text-cyber-white">{selectedTarget.name}</p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-cyber-light mb-1">Domain</h4>
                  <p className="text-neon-cyan font-mono">{selectedTarget.domain}</p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-cyber-light mb-1">Status</h4>
                  <span className={`px-2 py-1 rounded text-xs font-bold ${
                    selectedTarget.is_active ? 'bg-neon-green bg-opacity-20 text-neon-green' : 'bg-cyber-gray bg-opacity-20 text-cyber-gray'
                  }`}>
                    {selectedTarget.is_active ? 'ACTIVE' : 'INACTIVE'}
                  </span>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-cyber-light mb-1">Created</h4>
                  <p className="text-cyber-white">{new Date(selectedTarget.created_at).toLocaleDateString()}</p>
                </div>
              </div>
              
              {selectedTarget.description && (
                <div>
                  <h4 className="text-sm font-medium text-cyber-light mb-1">Description</h4>
                  <p className="text-cyber-white">{selectedTarget.description}</p>
                </div>
              )}
              
              {selectedTarget.scope && selectedTarget.scope.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-cyber-light mb-2">Scope</h4>
                  <div className="space-y-1">
                    {selectedTarget.scope.map((item: string, index: number) => (
                      <span key={index} className="inline-block bg-neon-green/10 text-neon-green px-2 py-1 rounded text-xs mr-2">
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              
              {selectedTarget.out_of_scope && selectedTarget.out_of_scope.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-cyber-light mb-2">Out of Scope</h4>
                  <div className="space-y-1">
                    {selectedTarget.out_of_scope.map((item: string, index: number) => (
                      <span key={index} className="inline-block bg-neon-red/10 text-neon-red px-2 py-1 rounded text-xs mr-2">
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              
              <div className="pt-4">
                <button
                  onClick={() => setShowDetailsModal(false)}
                  className="bg-primary hover:bg-primary/80 text-cyber-black font-medium py-2 px-4 rounded-md transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
};

export default Targets; 