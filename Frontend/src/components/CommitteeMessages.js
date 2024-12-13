import React, { useEffect, useState } from 'react';
import axios from '../utils/axios';
import { useParams } from 'react-router-dom';
import { Container, Typography, List, ListItem, ListItemText, TextField, Button, Box, CircularProgress, Snackbar, Alert } from '@mui/material';

const CommitteeMessages = () => {
  const { id } = useParams(); // Committee ID
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [attachment, setAttachment] = useState(null);
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [notification, setNotification] = useState({ open: false, message: '', severity: 'success' });

  useEffect(() => {
    fetchMessages();
    // Optionally, set up polling or WebSockets for real-time updates
  }, [id]);

  const fetchMessages = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`/Messages/${id}`);
      setMessages(response.data);
    } catch (error) {
      console.error(error);
      setNotification({ open: true, message: 'Failed to fetch messages.', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleSendMessage = async () => {
    if (!newMessage.trim() && !attachment) {
      setNotification({ open: true, message: 'Message cannot be empty.', severity: 'warning' });
      return;
    }

    setSending(true);
    try {
      const formData = new FormData();
      formData.append('CommitteeId', id);
      formData.append('Content', newMessage);
      if (attachment) {
        formData.append('File', attachment);
      }

      const response = await axios.post('/Messages/UploadAndSend', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      const newMsg = response.data;
      setMessages([...messages, {
        id: newMsg.id,
        Sender: newMsg.senderUserId, // Optionally fetch sender's username
        Content: newMsg.content,
        SentAt: newMsg.sentAt,
        attachmentPath: newMsg.attachmentPath
      }]);
      setNewMessage('');
      setAttachment(null);
      setNotification({ open: true, message: 'Message sent successfully.', severity: 'success' });
    } catch (error) {
      console.error(error);
      setNotification({ open: true, message: 'Failed to send message.', severity: 'error' });
    } finally {
      setSending(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Typography variant="h5" gutterBottom>
        Committee Messages
      </Typography>
      {loading ? (
        <CircularProgress />
      ) : (
        <List sx={{ maxHeight: '60vh', overflow: 'auto' }}>
          {messages.map(msg => (
            <ListItem key={msg.id} alignItems="flex-start">
              <ListItemText
                primary={`${msg.Sender}: ${msg.Content}`}
                secondary={
                  <>
                    <Typography variant="caption">{new Date(msg.SentAt).toLocaleString()}</Typography>
                    {msg.attachmentPath && (
                      <Button
                        variant="text"
                        color="primary"
                        href={msg.attachmentPath}
                        target="_blank"
                        sx={{ ml: 2 }}
                      >
                        Download Attachment
                      </Button>
                    )}
                  </>
                }
              />
            </ListItem>
          ))}
        </List>
      )}
      <Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
        <TextField
          label="New Message"
          variant="outlined"
          fullWidth
          multiline
          rows={2}
          value={newMessage}
          onChange={(e) => setNewMessage(e.target.value)}
        />
        <input
          type="file"
          onChange={(e) => setAttachment(e.target.files[0])}
          accept=".pdf,.doc,.docx,.png,.jpg,.jpeg,.txt"
        />
        <Button variant="contained" color="primary" onClick={handleSendMessage} disabled={sending}>
          {sending ? <CircularProgress size={24} /> : 'Send'}
        </Button>
      </Box>

      {/* Notification Snackbar */}
      <Snackbar open={notification.open} autoHideDuration={6000} onClose={() => setNotification({ ...notification, open: false })}>
        <Alert onClose={() => setNotification({ ...notification, open: false })} severity={notification.severity} sx={{ width: '100%' }}>
          {notification.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default CommitteeMessages;
