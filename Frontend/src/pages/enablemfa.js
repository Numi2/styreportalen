import React, { useState } from 'react';
import axios from '../utils/axios';
import { Container, Typography, Button, Dialog, DialogTitle, DialogContent, DialogActions, TextField, CircularProgress, Snackbar, Alert } from '@mui/material';

const EnableMfa = () => {
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [notification, setNotification] = useState({ open: false, message: '', severity: 'success' });

  const handleEnableMfa = async () => {
    setLoading(true);
    try {
      await axios.post('/Auth/EnableMfa');
      setNotification({ open: true, message: 'MFA token sent to your email.', severity: 'success' });
      setOpen(true);
    } catch (error) {
      console.error(error);
      setNotification({ open: true, message: 'Failed to send MFA token.', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyMfa = async () => {
    if (!token) {
      setNotification({ open: true, message: 'Please enter the MFA token.', severity: 'warning' });
      return;
    }

    setLoading(true);
    try {
      await axios.post('/Auth/VerifyMfa', { token });
      setNotification({ open: true, message: 'MFA enabled successfully.', severity: 'success' });
      setOpen(false);
    } catch (error) {
      console.error(error);
      setNotification({ open: true, message: 'Invalid MFA token.', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="sm" sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>
        Multi-Factor Authentication (MFA)
      </Typography>
      <Button variant="contained" color="primary" onClick={handleEnableMfa} disabled={loading}>
        {loading ? <CircularProgress size={24} /> : 'Enable MFA'}
      </Button>

      {/* Verification Dialog */}
      <Dialog open={open} onClose={() => setOpen(false)}>
        <DialogTitle>Verify MFA Token</DialogTitle>
        <DialogContent>
          <TextField
            label="MFA Token"
            variant="outlined"
            fullWidth
            margin="normal"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={handleVerifyMfa} variant="contained" color="primary" disabled={loading}>
            {loading ? <CircularProgress size={24} /> : 'Verify'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Notification Snackbar */}
      <Snackbar open={notification.open} autoHideDuration={6000} onClose={() => setNotification({ ...notification, open: false })}>
        <Alert onClose={() => setNotification({ ...notification, open: false })} severity={notification.severity} sx={{ width: '100%' }}>
          {notification.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default EnableMfa;