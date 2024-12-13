import React, { useEffect, useState } from 'react';
import axios from '../utils/axios';
import { Container, Typography, List, ListItem, ListItemText, Button, Box, CircularProgress, Dialog, DialogTitle, DialogContent, DialogActions } from '@mui/material';
import { Link } from 'react-router-dom';

const Documents = () => {
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [selectedDocument, setSelectedDocument] = useState(null);

  useEffect(() => {
    fetchDocuments();
  }, []);

  const fetchDocuments = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/Documents');
      setDocuments(response.data.data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = (id, title) => {
    window.open(`/api/Documents/${id}/Download`, '_blank');
  };

  const handleOpenVersions = (id) => {
    setSelectedDocument(id);
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    setSelectedDocument(null);
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>
        Documents
      </Typography>
      {loading ? (
        <CircularProgress />
      ) : (
        <List>
          {documents.map(doc => (
            <ListItem key={doc.id} divider>
              <ListItemText primary={doc.title} />
              <Button variant="outlined" onClick={() => handleDownload(doc.id, doc.title)} sx={{ mr: 1 }}>
                Download
              </Button>
              <Button variant="outlined" onClick={() => handleOpenVersions(doc.id)}>
                Versions
              </Button>
              <Button variant="outlined" component={Link} to={`/documents/${doc.id}/annotate`} sx={{ ml: 1 }}>
                Annotate
              </Button>
            </ListItem>
          ))}
        </List>
      )}

      {/* Versions Dialog */}
      <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
        <DialogTitle>Version History</DialogTitle>
        <DialogContent>
          {/* Fetch and display version history here */}
          <Typography>Version history will be displayed here.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>Close</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default Documents;
