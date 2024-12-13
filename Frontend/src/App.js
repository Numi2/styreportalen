import React, { Suspense, lazy } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
// Import other components lazily
const Login = lazy(() => import('./pages/Login'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Documents = lazy(() => import('./pages/Documents'));
const Meetings = lazy(() => import('./pages/Meetings'));
const Committees = lazy(() => import('./pages/Committees'));
const ProtectedRoute = lazy(() => import('./components/ProtectedRoute'));

function App() {
  return (
    <Router>
      <Suspense fallback={<div>Loading...</div>}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route 
            path="/" 
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/documents" 
            element={
              <ProtectedRoute>
                <Documents />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/meetings" 
            element={
              <ProtectedRoute>
                <Meetings />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/committees" 
            element={
              <ProtectedRoute>
                <Committees />
              </ProtectedRoute>
            } 
          />
          {/* Add other routes as needed */}
        </Routes>
      </Suspense>
    </Router>
  );
}

export default App;