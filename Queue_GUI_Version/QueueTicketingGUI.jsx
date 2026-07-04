import React, { useState, useEffect } from 'react';
import { Users, Ticket, Clock, TrendingUp, UserCheck, UserPlus, List, BarChart3, ChevronRight, Sparkles } from 'lucide-react';

// ============================================================================
// QUEUE DATA STRUCTURE (Same logic as C++ version)
// ============================================================================
class QueueSystem {
  constructor() {
    this.customers = [];
    this.ticketCounter = 1;
    this.totalServed = 0;
    this.maxSize = 100;
  }

  generateTicket(name) {
    if (this.customers.length >= this.maxSize) {
      return { success: false, message: 'Queue is full!' };
    }
    
    const ticket = {
      id: this.ticketCounter,
      number: `T${String(this.ticketCounter).padStart(4, '0')}`,
      name: name || 'Customer',
      timestamp: new Date(),
      position: this.customers.length + 1
    };
    
    this.customers.push(ticket);
    this.ticketCounter++;
    
    return { success: true, ticket };
  }

  serveCustomer() {
    if (this.customers.length === 0) {
      return { success: false, message: 'No customers in queue!' };
    }
    
    const served = this.customers.shift();
    this.totalServed++;
    
    // Update positions
    this.customers.forEach((customer, index) => {
      customer.position = index + 1;
    });
    
    return { success: true, customer: served };
  }

  getNext() {
    return this.customers.length > 0 ? this.customers[0] : null;
  }

  getQueue() {
    return [...this.customers];
  }

  getStats() {
    return {
      totalGenerated: this.ticketCounter - 1,
      totalServed: this.totalServed,
      inQueue: this.customers.length,
      capacity: this.maxSize,
      utilization: ((this.customers.length / this.maxSize) * 100).toFixed(1)
    };
  }
}

// ============================================================================
// MAIN APP COMPONENT
// ============================================================================
export default function QueueTicketingSystem() {
  const [queue] = useState(() => new QueueSystem());
  const [, forceUpdate] = useState({});
  const [customerName, setCustomerName] = useState('');
  const [activeTab, setActiveTab] = useState('generate');
  const [notification, setNotification] = useState(null);
  const [animateTicket, setAnimateTicket] = useState(false);
  const [servedTicket, setServedTicket] = useState(null);

  const refresh = () => forceUpdate({});

  const showNotification = (message, type = 'success') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 3000);
  };

  const handleGenerateTicket = () => {
    const result = queue.generateTicket(customerName);
    
    if (result.success) {
      setAnimateTicket(true);
      showNotification(`Ticket ${result.ticket.number} generated!`, 'success');
      setCustomerName('');
      setTimeout(() => setAnimateTicket(false), 600);
    } else {
      showNotification(result.message, 'error');
    }
    
    refresh();
  };

  const handleServeCustomer = () => {
    const result = queue.serveCustomer();
    
    if (result.success) {
      setServedTicket(result.customer);
      showNotification(`Serving ${result.customer.name}`, 'success');
      setTimeout(() => setServedTicket(null), 3000);
    } else {
      showNotification(result.message, 'error');
    }
    
    refresh();
  };

  const stats = queue.getStats();
  const queueList = queue.getQueue();
  const nextCustomer = queue.getNext();

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      padding: '2rem 1rem',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Animated Background Elements */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        opacity: 0.1,
        pointerEvents: 'none'
      }}>
        {[...Array(20)].map((_, i) => (
          <div
            key={i}
            style={{
              position: 'absolute',
              width: `${Math.random() * 100 + 50}px`,
              height: `${Math.random() * 100 + 50}px`,
              borderRadius: '50%',
              background: 'white',
              top: `${Math.random() * 100}%`,
              left: `${Math.random() * 100}%`,
              animation: `float ${Math.random() * 10 + 10}s ease-in-out infinite`,
              animationDelay: `${Math.random() * 5}s`
            }}
          />
        ))}
      </div>

      <style>{`
        @keyframes float {
          0%, 100% { transform: translateY(0) translateX(0); }
          50% { transform: translateY(-20px) translateX(20px); }
        }
        
        @keyframes slideIn {
          from { transform: translateY(-20px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
        
        @keyframes pulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.05); }
        }
        
        @keyframes ticketPop {
          0% { transform: scale(0.8) rotate(-5deg); opacity: 0; }
          50% { transform: scale(1.1) rotate(2deg); }
          100% { transform: scale(1) rotate(0deg); opacity: 1; }
        }
        
        @keyframes shimmer {
          0% { background-position: -1000px 0; }
          100% { background-position: 1000px 0; }
        }
      `}</style>

      {/* Notification */}
      {notification && (
        <div style={{
          position: 'fixed',
          top: '2rem',
          right: '2rem',
          background: notification.type === 'success' ? '#10b981' : '#ef4444',
          color: 'white',
          padding: '1rem 1.5rem',
          borderRadius: '12px',
          boxShadow: '0 10px 40px rgba(0,0,0,0.2)',
          zIndex: 1000,
          animation: 'slideIn 0.3s ease-out',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontWeight: '600'
        }}>
          <Sparkles size={20} />
          {notification.message}
        </div>
      )}

      {/* Served Ticket Overlay */}
      {servedTicket && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0,0,0,0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 999,
          animation: 'slideIn 0.3s ease-out'
        }}>
          <div style={{
            background: 'white',
            padding: '3rem',
            borderRadius: '20px',
            textAlign: 'center',
            maxWidth: '500px',
            animation: 'ticketPop 0.5s ease-out'
          }}>
            <div style={{
              width: '80px',
              height: '80px',
              background: 'linear-gradient(135deg, #10b981, #059669)',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 1.5rem'
            }}>
              <UserCheck size={40} color="white" />
            </div>
            <h2 style={{ fontSize: '2rem', fontWeight: '800', color: '#1f2937', marginBottom: '0.5rem' }}>
              NOW SERVING
            </h2>
            <div style={{ fontSize: '3rem', fontWeight: '900', color: '#667eea', marginBottom: '0.5rem' }}>
              {servedTicket.number}
            </div>
            <div style={{ fontSize: '1.5rem', color: '#6b7280', fontWeight: '600' }}>
              {servedTicket.name}
            </div>
          </div>
        </div>
      )}

      <div style={{ maxWidth: '1400px', margin: '0 auto', position: 'relative', zIndex: 1 }}>
        {/* Header */}
        <div style={{
          textAlign: 'center',
          marginBottom: '3rem',
          animation: 'slideIn 0.6s ease-out'
        }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '1rem',
            background: 'rgba(255,255,255,0.15)',
            padding: '0.75rem 2rem',
            borderRadius: '50px',
            backdropFilter: 'blur(10px)',
            marginBottom: '1rem',
            border: '1px solid rgba(255,255,255,0.2)'
          }}>
            <Ticket size={28} color="white" />
            <h1 style={{
              fontSize: '2rem',
              fontWeight: '900',
              color: 'white',
              margin: 0,
              letterSpacing: '-0.02em'
            }}>
              Queue Ticketing System
            </h1>
          </div>
          <p style={{ color: 'rgba(255,255,255,0.9)', fontSize: '1.1rem', fontWeight: '500' }}>
            Modern Customer Service Management
          </p>
        </div>

        {/* Stats Cards */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '1.5rem',
          marginBottom: '2rem'
        }}>
          {[
            { icon: Ticket, label: 'Total Generated', value: stats.totalGenerated, color: '#3b82f6', gradient: 'linear-gradient(135deg, #3b82f6, #2563eb)' },
            { icon: UserCheck, label: 'Customers Served', value: stats.totalServed, color: '#10b981', gradient: 'linear-gradient(135deg, #10b981, #059669)' },
            { icon: Users, label: 'In Queue', value: stats.inQueue, color: '#f59e0b', gradient: 'linear-gradient(135deg, #f59e0b, #d97706)' },
            { icon: TrendingUp, label: 'Utilization', value: `${stats.utilization}%`, color: '#8b5cf6', gradient: 'linear-gradient(135deg, #8b5cf6, #7c3aed)' }
          ].map((stat, index) => (
            <div
              key={index}
              style={{
                background: 'white',
                borderRadius: '16px',
                padding: '1.5rem',
                boxShadow: '0 10px 40px rgba(0,0,0,0.1)',
                animation: `slideIn 0.6s ease-out ${index * 0.1}s both`,
                position: 'relative',
                overflow: 'hidden'
              }}
            >
              <div style={{
                position: 'absolute',
                top: 0,
                right: 0,
                width: '100px',
                height: '100px',
                background: stat.gradient,
                opacity: 0.1,
                borderRadius: '50%',
                transform: 'translate(30%, -30%)'
              }} />
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                <span style={{ color: '#6b7280', fontSize: '0.875rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {stat.label}
                </span>
                <div style={{
                  width: '40px',
                  height: '40px',
                  background: stat.gradient,
                  borderRadius: '10px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <stat.icon size={20} color="white" />
                </div>
              </div>
              <div style={{ fontSize: '2.5rem', fontWeight: '900', color: '#1f2937' }}>
                {stat.value}
              </div>
            </div>
          ))}
        </div>

        {/* Main Content */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '2rem',
          '@media (max-width: 1024px)': { gridTemplateColumns: '1fr' }
        }}>
          {/* Left Panel - Actions */}
          <div style={{
            background: 'white',
            borderRadius: '20px',
            padding: '2rem',
            boxShadow: '0 20px 60px rgba(0,0,0,0.15)',
            animation: 'slideIn 0.8s ease-out'
          }}>
            {/* Tab Navigation */}
            <div style={{
              display: 'flex',
              gap: '1rem',
              marginBottom: '2rem',
              background: '#f3f4f6',
              padding: '0.5rem',
              borderRadius: '12px'
            }}>
              {[
                { id: 'generate', label: 'Generate Ticket', icon: UserPlus },
                { id: 'serve', label: 'Serve Customer', icon: UserCheck }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  style={{
                    flex: 1,
                    padding: '0.875rem',
                    border: 'none',
                    borderRadius: '8px',
                    background: activeTab === tab.id ? 'linear-gradient(135deg, #667eea, #764ba2)' : 'transparent',
                    color: activeTab === tab.id ? 'white' : '#6b7280',
                    fontWeight: '700',
                    fontSize: '0.95rem',
                    cursor: 'pointer',
                    transition: 'all 0.3s ease',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '0.5rem'
                  }}
                >
                  <tab.icon size={18} />
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Generate Ticket Tab */}
            {activeTab === 'generate' && (
              <div style={{ animation: 'slideIn 0.3s ease-out' }}>
                <h3 style={{ fontSize: '1.5rem', fontWeight: '800', color: '#1f2937', marginBottom: '1.5rem' }}>
                  Add New Customer
                </h3>
                <div style={{ marginBottom: '1.5rem' }}>
                  <label style={{
                    display: 'block',
                    fontSize: '0.875rem',
                    fontWeight: '600',
                    color: '#374151',
                    marginBottom: '0.5rem',
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em'
                  }}>
                    Customer Name
                  </label>
                  <input
                    type="text"
                    value={customerName}
                    onChange={(e) => setCustomerName(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleGenerateTicket()}
                    placeholder="Enter customer name..."
                    style={{
                      width: '100%',
                      padding: '1rem',
                      border: '2px solid #e5e7eb',
                      borderRadius: '12px',
                      fontSize: '1rem',
                      outline: 'none',
                      transition: 'all 0.3s ease',
                      boxSizing: 'border-box'
                    }}
                    onFocus={(e) => e.target.style.borderColor = '#667eea'}
                    onBlur={(e) => e.target.style.borderColor = '#e5e7eb'}
                  />
                </div>
                <button
                  onClick={handleGenerateTicket}
                  style={{
                    width: '100%',
                    padding: '1.25rem',
                    border: 'none',
                    borderRadius: '12px',
                    background: 'linear-gradient(135deg, #667eea, #764ba2)',
                    color: 'white',
                    fontSize: '1.1rem',
                    fontWeight: '700',
                    cursor: 'pointer',
                    transition: 'all 0.3s ease',
                    boxShadow: '0 10px 30px rgba(102, 126, 234, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '0.75rem',
                    animation: animateTicket ? 'pulse 0.6s ease-out' : 'none'
                  }}
                  onMouseEnter={(e) => {
                    e.target.style.transform = 'translateY(-2px)';
                    e.target.style.boxShadow = '0 15px 40px rgba(102, 126, 234, 0.4)';
                  }}
                  onMouseLeave={(e) => {
                    e.target.style.transform = 'translateY(0)';
                    e.target.style.boxShadow = '0 10px 30px rgba(102, 126, 234, 0.3)';
                  }}
                >
                  <Ticket size={24} />
                  Generate Ticket
                  <ChevronRight size={24} />
                </button>

                {/* Next Customer Preview */}
                {nextCustomer && (
                  <div style={{
                    marginTop: '2rem',
                    padding: '1.5rem',
                    background: 'linear-gradient(135deg, #fef3c7, #fde68a)',
                    borderRadius: '12px',
                    border: '2px solid #fbbf24'
                  }}>
                    <div style={{ fontSize: '0.875rem', fontWeight: '700', color: '#92400e', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      Next to be Served
                    </div>
                    <div style={{ fontSize: '1.5rem', fontWeight: '900', color: '#78350f' }}>
                      {nextCustomer.number}
                    </div>
                    <div style={{ fontSize: '1.1rem', color: '#92400e', fontWeight: '600' }}>
                      {nextCustomer.name}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Serve Customer Tab */}
            {activeTab === 'serve' && (
              <div style={{ animation: 'slideIn 0.3s ease-out' }}>
                <h3 style={{ fontSize: '1.5rem', fontWeight: '800', color: '#1f2937', marginBottom: '1.5rem' }}>
                  Serve Next Customer
                </h3>
                {nextCustomer ? (
                  <>
                    <div style={{
                      background: 'linear-gradient(135deg, #f0fdf4, #dcfce7)',
                      padding: '2rem',
                      borderRadius: '16px',
                      marginBottom: '1.5rem',
                      border: '2px solid #10b981',
                      textAlign: 'center'
                    }}>
                      <div style={{ fontSize: '0.875rem', fontWeight: '700', color: '#065f46', marginBottom: '1rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Currently Serving
                      </div>
                      <div style={{ fontSize: '3rem', fontWeight: '900', color: '#047857', marginBottom: '0.5rem' }}>
                        {nextCustomer.number}
                      </div>
                      <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#059669' }}>
                        {nextCustomer.name}
                      </div>
                      <div style={{
                        marginTop: '1rem',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '0.5rem',
                        color: '#065f46',
                        fontSize: '0.95rem',
                        fontWeight: '600'
                      }}>
                        <Clock size={16} />
                        Position: #{nextCustomer.position}
                      </div>
                    </div>
                    <button
                      onClick={handleServeCustomer}
                      style={{
                        width: '100%',
                        padding: '1.25rem',
                        border: 'none',
                        borderRadius: '12px',
                        background: 'linear-gradient(135deg, #10b981, #059669)',
                        color: 'white',
                        fontSize: '1.1rem',
                        fontWeight: '700',
                        cursor: 'pointer',
                        transition: 'all 0.3s ease',
                        boxShadow: '0 10px 30px rgba(16, 185, 129, 0.3)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '0.75rem'
                      }}
                      onMouseEnter={(e) => {
                        e.target.style.transform = 'translateY(-2px)';
                        e.target.style.boxShadow = '0 15px 40px rgba(16, 185, 129, 0.4)';
                      }}
                      onMouseLeave={(e) => {
                        e.target.style.transform = 'translateY(0)';
                        e.target.style.boxShadow = '0 10px 30px rgba(16, 185, 129, 0.3)';
                      }}
                    >
                      <UserCheck size={24} />
                      Mark as Served
                      <ChevronRight size={24} />
                    </button>
                  </>
                ) : (
                  <div style={{
                    textAlign: 'center',
                    padding: '3rem 1rem',
                    color: '#9ca3af'
                  }}>
                    <Users size={64} strokeWidth={1.5} style={{ margin: '0 auto 1rem', opacity: 0.3 }} />
                    <p style={{ fontSize: '1.1rem', fontWeight: '600' }}>No customers in queue</p>
                    <p style={{ fontSize: '0.95rem' }}>Generate tickets to start serving</p>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Right Panel - Queue Display */}
          <div style={{
            background: 'white',
            borderRadius: '20px',
            padding: '2rem',
            boxShadow: '0 20px 60px rgba(0,0,0,0.15)',
            animation: 'slideIn 0.9s ease-out',
            maxHeight: '600px',
            display: 'flex',
            flexDirection: 'column'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
              <h3 style={{ fontSize: '1.5rem', fontWeight: '800', color: '#1f2937', margin: 0, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <List size={28} />
                Current Queue
              </h3>
              <div style={{
                background: 'linear-gradient(135deg, #667eea, #764ba2)',
                color: 'white',
                padding: '0.5rem 1rem',
                borderRadius: '50px',
                fontSize: '0.875rem',
                fontWeight: '700'
              }}>
                {queueList.length} Waiting
              </div>
            </div>

            <div style={{
              flex: 1,
              overflowY: 'auto',
              paddingRight: '0.5rem'
            }}>
              {queueList.length === 0 ? (
                <div style={{
                  textAlign: 'center',
                  padding: '3rem 1rem',
                  color: '#9ca3af'
                }}>
                  <Users size={64} strokeWidth={1.5} style={{ margin: '0 auto 1rem', opacity: 0.3 }} />
                  <p style={{ fontSize: '1.1rem', fontWeight: '600' }}>Queue is empty</p>
                  <p style={{ fontSize: '0.95rem' }}>Start by generating tickets</p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {queueList.map((customer, index) => (
                    <div
                      key={customer.id}
                      style={{
                        background: index === 0 
                          ? 'linear-gradient(135deg, #fef3c7, #fde68a)'
                          : '#f9fafb',
                        padding: '1.25rem',
                        borderRadius: '12px',
                        border: index === 0 ? '2px solid #fbbf24' : '2px solid #e5e7eb',
                        transition: 'all 0.3s ease',
                        animation: `slideIn 0.3s ease-out ${index * 0.05}s both`,
                        cursor: 'pointer'
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.transform = 'translateX(5px)';
                        e.currentTarget.style.boxShadow = '0 5px 20px rgba(0,0,0,0.1)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.transform = 'translateX(0)';
                        e.currentTarget.style.boxShadow = 'none';
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                        <span style={{
                          fontSize: '1.5rem',
                          fontWeight: '900',
                          color: index === 0 ? '#92400e' : '#667eea'
                        }}>
                          {customer.number}
                        </span>
                        <div style={{
                          width: '36px',
                          height: '36px',
                          borderRadius: '50%',
                          background: index === 0 
                            ? 'linear-gradient(135deg, #fbbf24, #f59e0b)'
                            : 'linear-gradient(135deg, #667eea, #764ba2)',
                          color: 'white',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '0.875rem',
                          fontWeight: '800'
                        }}>
                          #{customer.position}
                        </div>
                      </div>
                      <div style={{
                        fontSize: '1.1rem',
                        fontWeight: '600',
                        color: '#374151'
                      }}>
                        {customer.name}
                      </div>
                      {index === 0 && (
                        <div style={{
                          marginTop: '0.75rem',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.5rem',
                          background: '#fbbf24',
                          color: '#78350f',
                          padding: '0.375rem 0.75rem',
                          borderRadius: '50px',
                          fontSize: '0.75rem',
                          fontWeight: '700',
                          textTransform: 'uppercase',
                          letterSpacing: '0.05em'
                        }}>
                          <Sparkles size={14} />
                          Next in Line
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}