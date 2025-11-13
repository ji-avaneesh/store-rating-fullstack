import React, { useState, createContext, useContext, useEffect } from 'react';
import { Routes, Route, useNavigate, Link, Navigate } from 'react-router-dom';
import axios from 'axios';

// हमारे बैकएंड का बेस URL
const API_URL = 'http://localhost:5000/api';

// =====================================================================
// 1. Auth Context 
// =====================================================================
const AuthContext = createContext(null);
const useAuth = () => useContext(AuthContext);

function AuthProvider({ children }) {
  const [token, setToken] = useState(localStorage.getItem('token') || null);
  const [user, setUser] = useState(JSON.parse(localStorage.getItem('user')) || null);
  const navigate = useNavigate();

  const loginAction = async (email, password) => {
    try {
      const response = await axios.post(`${API_URL}/auth/login`, { email, password });
      const { token, user } = response.data;
      setToken(token);
      setUser(user);
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(user));
      navigate('/'); 
      return { success: true };
    } catch (err) {
      return { success: false, error: err.response?.data?.error || 'login failed' };
    }
  };

  const logoutAction = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/login');
  };
  
  const authAxios = axios.create({ baseURL: API_URL });
  authAxios.interceptors.request.use((config) => {
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  });

  return (
    <AuthContext.Provider value={{ token, user, loginAction, logoutAction, authAxios }}>
      {children}
    </AuthContext.Provider>
  );
}

// =====================================================================
// 2.  (Components)
// =====================================================================

// --- ProtectedRoute  ---
function ProtectedRoute({ children }) {
  const { token } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  return children;
}

// --- Layout  ---
function Layout({ children }) {
  return (
    <div className="flex justify-center min-h-screen bg-gray-100 font-sans py-12 px-4">
      <div className="w-full max-w-lg md:max-w-4xl">
        {children}
      </div>
    </div>
  );
}

// --- Login ---
function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const { loginAction } = useAuth();
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    const result = await loginAction(email, password);
    if (!result.success) setError(result.error);
  };

  return (
    <div className="p-8 space-y-6 bg-white rounded-lg shadow-xl max-w-md mx-auto">
      <h2 className="text-3xl font-bold text-center text-gray-900">Login</h2>
      {error && <Alert type="error">{error}</Alert>}
      <form className="space-y-4" onSubmit={handleSubmit}>
        <Input label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <Input label="Password "Paa type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit" className="w-full px-4 py-2 font-medium text-white bg-indigo-600 rounded-md shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
          Login 
        </button>
      </form>
      <p className="text-sm text-center text-gray-600">
        register here{' '}
        <Link to="/register" className="font-medium text-indigo-600 hover:text-indigo-500">
          Register here
        </Link>
      </p>
    </div>
  );
}

// --- Register  ---
function Register() {
  const [formData, setFormData] = useState({ name: '', email: '', password: '', address: '' });
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);
  const navigate = useNavigate();

  const handleChange = (e) => setFormData({ ...formData, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setMessage(null);
    
    // Frontend Validation
    if (formData.name.length < 20 || formData.name.length > 60) { setError('The name should be between 20 to 60 characters.'); return; }
    if (formData.address.length > 400) { setError('The address must be less than 400 characters.'); return; }
    if (formData.password.length < 8 || formData.password.length > 16 || !/[A-Z]/.test(formData.password) || !/[!@#$%^&*(),.?":{}|<>]/.test(formData.password)) {
      setError('Password must be 8-16 characters, 1 Uppercase, 1 Special character.');
      return;
    }

    try {
      const response = await axios.post(`${API_URL}/auth/register`, formData);
      setMessage(response.data.message + ' You can now login.');
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      setError(err.response?.data?.error || 'something went wrong');
    }
  };

  return (
    <div className="p-8 space-y-6 bg-white rounded-lg shadow-xl max-w-md mx-auto">
      <h2 className="text-3xl font-bold text-center text-gray-900">Create new account</h2>
      {error && <Alert type="error">{error}</Alert>}
      {message && <Alert type="success">{message}</Alert>}
      <form className="space-y-4" onSubmit={handleSubmit}>
        <Input label="Full Name" name="name" value={formData.name} onChange={handleChange} />
        <Input label="Email" name="email" type="email" value={formData.email} onChange={handleChange} />
        <Input label="Password " name="password" type="password" value={formData.password} onChange={handleChange} />
        <Input label="Address " name="address" type="textarea" value={formData.address} onChange={handleChange} />
        <button type="submit " className="w-full px-4 py-2 font-medium text-white bg-indigo-600 rounded-md shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
          Register
        </button>
      </form>
      <p className="text-sm text-center text-gray-600">
        Already have an account?{' '}
        <Link to="/login" className="font-medium text-indigo-600 hover:text-indigo-500">
          Login Here 
        </Link>
      </p>
    </div>
  );
}

// --- Main Dashboard ---
function Dashboard() {
  const { user, logoutAction } = useAuth();

  const renderDashboard = () => {
    switch (user.role) {
      case 'admin': return <AdminDashboard />;
      case 'owner': return <OwnerDashboard />;
      case 'user': return <UserDashboard />;
      default: return <p>No roles found.</p>;
    }
  };

  return (
    <div className="p-8 space-y-6 bg-white rounded-lg shadow-xl">
      <div className="flex flex-col sm:flex-row justify-between sm:items-center space-y-2 sm:space-y-0">
        <h2 className="text-2xl font-bold text-gray-900">
          Welcome, {user.name} 
          <span className="text-base font-medium text-indigo-600 ml-2">({user.role})</span>
        </h2>
        <button
          onClick={logoutAction}
          className="px-4 py-2 font-medium text-white bg-red-600 rounded-md shadow-sm hover:bg-red-700"
        >
          Log out
        </button>
      </div>
      
      {/*Dash board based on Role  */}
      <div className="border-t border-gray-200 pt-6">
        {renderDashboard()}
      </div>

      {/* (New Password Update ) */}
      <div className="border-t border-gray-200 pt-6">
        <PasswordUpdate />
      </div>
    </div>
  );
}

// --- Admin Dashboard ---
function AdminDashboard() {
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [stores, setStores] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const { authAxios } = useAuth(); 

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);
        const [statsRes, usersRes, storesRes] = await Promise.all([
          authAxios.get('/admin/dashboard'),
          authAxios.get('/admin/users'),
          authAxios.get('/admin/stores'),
        ]);
        setStats(statsRes.data);
        setUsers(usersRes.data);
        setStores(storesRes.data);
      } catch (err) {
        setError(err.response?.data?.error || 'failed to fetch data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [authAxios]); 

  if (loading) return <p className="text-center">Loading Dashboard ...</p>;
  if (error) return <Alert type="error">{error}</Alert>;

  return (
    <div className="space-y-8">
      <h3 className="text-xl font-semibold text-gray-800">system statistics</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard title="Toatal Users" value={stats.totalUsers} />
        <StatCard title="Toatal Stores" value={stats.totalStores} />
        <StatCard title="Toatal Retings" value={stats.totalRatings} />
      </div>

      <h3 className="text-xl font-semibold text-gray-800">User's list</h3>
      <div className="overflow-x-auto rounded-lg shadow border border-gray-200">
        <table className="min-w-full bg-white">
          <thead className="bg-gray-50">
            <tr>
              <Th>ID</Th> <Th>Name</Th> <Th>Email</Th> <Th>Role</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {users.map(user => (
              <tr key={user.id}>
                <Td>{user.id}</Td>
                <Td>{user.name}</Td>
                <Td>{user.email}</Td>
                <Td><span className={`px-2 py-1 text-xs font-medium rounded-full ${
                  user.role === 'admin' ? 'bg-red-100 text-red-800' :
                  user.role === 'owner' ? 'bg-yellow-100 text-yellow-800' :
                  'bg-green-100 text-green-800'
                }`}>{user.role}</span></Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3 className="text-xl font-semibold text-gray-800">Store list</h3>
      <div className="overflow-x-auto rounded-lg shadow border border-gray-200">
        <table className="min-w-full bg-white">
          <thead className="bg-gray-50">
            <tr>
              <Th>ID</Th> <Th>Name of Sotre </Th> <Th>Owner ID</Th> <Th>Average rating </Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {stores.map(store => (
              <tr key={store.id}>
                <Td>{store.id}</Td>
                <Td>{store.name}</Td>
                <Td>{store.owner_id}</Td>
                <Td>{store.average_rating} ⭐</Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- Owner Dashboard ---
function OwnerDashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const { authAxios } = useAuth();

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await authAxios.get('/owner/dashboard');
        setData(response.data);
      } catch (err) {
        setError(err.response?.data?.error || 'failed to fetch data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [authAxios]);

  if (loading) return <p className="text-center">Loading Dashboard ...</p>;
  if (error) return <Alert type="error">{error}</Alert>;
  if (!data) return null;

  return (
    <div className="space-y-8">
      <h3 className="text-xl font-semibold text-gray-800">My Store Statistics</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <StatCard title="Name of Store " value={data.storeName} />
        <StatCard title=" Average Rating" value={`${data.averageRating} ⭐`} />
      </div>

      <h3 className="text-xl font-semibold text-gray-800">My store ratings</h3>
      <div className="overflow-x-auto rounded-lg shadow border border-gray-200">
        <table className="min-w-full bg-white">
          <thead className="bg-gray-50">
            <tr>
              <Th>Name of User </Th>
              <Th> Email of User </Th>
              <Th>The given rating</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {data.ratingsList.length === 0 ? (
              <tr>
                <Td colSpan="3" className="text-center">No ratings yet.</Td>
              </tr>
            ) : (
              data.ratingsList.map((rating, index) => (
                <tr key={index}>
                  <Td>{rating.user_name}</Td>
                  <Td>{rating.user_email}</Td>
                  <Td>{rating.rating} ⭐</Td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- User Dashboard  ---

function UserDashboard() {
  const [stores, setStores] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');   //    Search by Name 
  const [addressTerm, setAddressTerm] = useState(''); //  Search by Address 
  const { authAxios } = useAuth();
  
  const fetchStores = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await authAxios.get('/user/stores', {
        params: { name: searchTerm, address: addressTerm }
      });
      setStores(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to fetch stores');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStores();
  }, [authAxios]); 
  
  const handleSearch = (e) => {
    e.preventDefault();
    fetchStores();
  };
  
  const handleRatingSubmit = async (storeId, rating) => {
    try {
      await authAxios.post('/user/ratings', {
        store_id: storeId,
        rating: rating
      });
      fetchStores(); // Refresh List 
    } catch (err) {
      alert('failed to rate ' + (err.response?.data?.error || 'Server Error !! '));
    }
  };

  if (loading) return <p className="text-center">Loading...</p>;
  if (error) return <Alert type="error">{error}</Alert>;

  return (
    <div className="space-y-6">
      <h3 className="text-xl font-semibold text-gray-800">Search Stores </h3>
      <form onSubmit={handleSearch} className="grid grid-cols-1 sm:grid-cols-3 gap-4 p-4 bg-gray-50 rounded-lg shadow">
        <Input label="Search by Name " name="search" type="text" value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} required={false} />
        <Input label="Search by Address " name="address" type="text" value={addressTerm} onChange={(e) => setAddressTerm(e.target.value)} required={false} />
        <button type="submit" className="sm:col-start-3 sm:self-end px-4 py-2 font-medium text-white bg-indigo-600 rounded-md shadow-sm hover:bg-indigo-700">
          Search
        </button>
      </form>

      <h3 className="text-xl font-semibold text-gray-800">All stores</h3>
      <div className="space-y-4">
        {stores.length === 0 ? (
          <p className="text-center text-gray-500">NO any store </p>
        ) : (
          stores.map(store => (
            <StoreCard 
              key={store.id} 
              store={store} 
              onRate={handleRatingSubmit} 
            />
          ))
        )}
      </div>
    </div>
  );
}

// ---  Password Update  ---
function PasswordUpdate() {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);
  const { authAxios } = useAuth();
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setMessage(null);
    
    // Validate the Password on frontend 
    if (newPassword.length < 8 || newPassword.length > 16 || !/[A-Z]/.test(newPassword) || !/[!@#$%^&*(),.?":{}|<>]/.test(newPassword)) {
      setError(' New Password should be atleast 8-16 letters, where 1 Upercase, 1 Special  ');
      return;
    }
    
    try {
      const response = await authAxios.patch('/auth/update-password', {
        oldPassword,
        newPassword
      });
      setMessage(response.data.message);
      setOldPassword('');
      setNewPassword('');
    } catch (err) {
      setError(err.response?.data?.error || 'Update Unsuccessfull !! ');
    }
  };

  return (
    <div className="space-y-4">
      <h3 className="text-xl font-semibold text-gray-800">Update Password </h3>
      {error && <Alert type="error">{error}</Alert>}
      {message && <Alert type="success">{message}</Alert>}
      <form onSubmit={handleSubmit} className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Input label="Old Password " name="oldPassword" type="password" value={oldPassword} onChange={(e) => setOldPassword(e.target.value)} />
        <Input label="New Password " name="newPassword" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
        <button type="submit" className="sm:self-end px-4 py-2 font-medium text-white bg-indigo-600 rounded-md shadow-sm hover:bg-indigo-700">
          Update
        </button>
      </form>
    </div>
  );
}

// 4. Utility componants

function Input({ label, type = 'text', name, value, onChange, placeholder, required = true }) {
  const commonProps = {
    name: name || label.toLowerCase(), value, onChange, placeholder, required,
    className: "w-full px-3 py-2 mt-1 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
  };
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700">{label}:</label>
      {type === 'textarea' ? <textarea {...commonProps} required={false} /> : <input type={type} {...commonProps} />}
    </div>
  );
}

function Alert({ type, children }) {
  const baseClasses = "p-3 rounded text-center";
  const typeClasses = type === 'error' 
    ? "text-red-600 bg-red-100" 
    : "text-green-600 bg-green-100";
  return <div className={`${baseClasses} ${typeClasses}`}>{children}</div>;
}

function StatCard({ title, value }) {
  return (
    <div className="p-4 bg-gray-50 rounded-lg shadow">
      <h4 className="text-sm font-medium text-gray-500 uppercase">{title}</h4>
      <p className="text-3xl font-bold text-gray-900">{value}</p>
    </div>
  );
}

function Th({ children }) {
  return <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{children}</th>;
}
function Td({ children }) {
  return <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{children}</td>;
}

// App 

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Layout><Login /></Layout>} />
        <Route path="/register" element={<Layout><Register /></Layout>} />
        <Route 
          path="/" 
          element={
            <ProtectedRoute>
              <Layout>
                <Dashboard />
              </Layout>
            </ProtectedRoute>
          } 
        />
      </Routes>
    </AuthProvider>
  );
}

export default App;