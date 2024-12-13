import React, { useEffect, useState } from 'react';
import axios from '../utils/axios';
import { Container, Typography, List, ListItem, ListItemText, Button, CircularProgress } from '@mui/material';
import { SaveAlt, CalendarToday } from '@mui/icons-material';

const Meetings = () => {
  const [meetings, setMeetings] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchMeetings();
  }, []);

  const fetchMeetings = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/Meetings');
      setMeetings(response.data.data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleExportICS = (meetingId) => {
    window.open(`/api/Meetings/${meetingId}/ExportICS`, '_blank');
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>
        Meetings
      </Typography>
      {loading ? (
        <CircularProgress />
      ) : (
        <List>
          {meetings.map(meeting => (
            <ListItem key={meeting.id} divider>
              <ListItemText primary={meeting.title} secondary={new Date(meeting.scheduledDateTime).toLocaleString()} />
              <Button 
                variant="outlined" 
                onClick={() => handleExportICS(meeting.id)} 
                startIcon={<SaveAlt />}
                sx={{ mr: 1 }}
              >
                Export ICS
              </Button>
              <Button 
                variant="outlined" 
                onClick={() => handleExportICS(meeting.id)} 
                startIcon={<CalendarToday />}
              >
                Add to Calendar
              </Button>
            </ListItem>
          ))}
        </List>
      )}
    </Container>
  );
};

export default Meetings;
