// ========
// BACKEND API - AI RÉCEPTIONNISTE
// Node.js + Express + PostgreSQL
// ===========

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;


// ======
// CONFIGURATION
// ========

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',

			  
  port: process.env.DB_PORT || 5432,

	   
  database: process.env.DB_NAME || 'ai_receptionist',

					
  user: process.env.DB_USER || 'postgres',

			 
  password: process.env.DB_PASSWORD || 'password',

			 
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

										   

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
											   
const HUGGINGFACE_API_KEY = process.env.HUGGINGFACE_API_KEY || "";


// =====
// MIDDLEWARE
// =======
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token d\'authentification requis' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token invalide ou expiré' });
        }
        req.user = user;
        next();
    });
};

// ==================
// FONCTIONS UTILITAIRES
// ==================

// Fonction pour analyser l'intention du message (NLP simple + Hugging Face)
const analyzelntent = async (message) => {
    const lowerMessage = message.toLowerCase();
    
    // Détection simple basée sur des mots-clés
    if (lowerMessage.includes('rendez-vous') || lowerMessage.includes('rdv') ||
        lowerMessage.includes('consultation') || lowerMessage.includes('voir')) {
        return { intent: 'schedule_appointment', confidence: 0.9 };
    }
    if (lowerMessage.includes('annuler') || lowerMessage.includes('reporter')) {
        return { intent: 'cancel_appointment', confidence: 0.85 };
    }
    if (lowerMessage.includes('horaire') || lowerMessage.includes('ouvert') ||
        lowerMessage.includes('disponible')) {
        return { intent: 'check_availability', confidence: 0.8 };
    }
    
    // Analyse plus avancée via API Hugging Face si la clé est présente
    if (HUGGINGFACE_API_KEY) {
        try {
            const response = await axios.post(
                'https://api-inference.huggingface.co/models/facebook/bart-large-mnli',
                {
                    inputs: message,
                    parameters: {
                        candidate_labels: [
                            'schedule appointment',
                            'cancel appointment',
                            'check availability',
                            'general inquiry',
                            'emergency'
                        ],
                    },
                },
                {
                    headers: {
                        'Authorization': `Bearer ${HUGGINGFACE_API_KEY}`,
                        'Content-Type': 'application/json'
                    }
                }
            );
            const topLabel = response.data.labels;
            const confidence = response.data.scores;

            return {
                intent: topLabel.replace(' ', '_'),
                confidence: confidence
            };
        } catch (error) {
            console.error('Erreur HuggingFace API:', error.message);
            // Retour au fallback en cas d'échec API
            return { intent: 'general_inquiry', confidence: 0.5 }; 
        }
    }
    
    // Fallback par défaut si aucune détection simple et pas de clé HF
    return { intent: 'general_inquiry', confidence: 0.5 };
};

// Générer une réponse AI (basée sur l'état ou l'intention)
const generateAIResponse = async (message, conversationState) => {
    const responses = {
        greeting: "Bonjour! Je suis votre assistant médical AI. Je peux vous aider à prendre rendez-vous. Quel est votre nom?",
        get_name: "Merci! Pour vous contacter, quel est votre numéro de téléphone?",
        get_phone: "Parfait! Quelle date vous conviendrait pour votre rendez-vous?",
        get_date: "Très bien! Quelle heure préférez-vous? (Nos horaires: 9h-12h et 14h-18h)",
        get_time: "Excellent! Pouvez-vous me dire le motif de votre consultation?",
        get_reason: "Merci. Y a-t-il des informations supplémentaires que le médecin devrait connaître?",
        confirmation: "Parfait! Je prépare votre récapitulatif de rendez-vous..."
    };
    return responses || "Comment puis-je vous aider?";
};


// ==================
// ROUTES - AUTHENTIFICATION
// ==================

// Connexion médecin
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1 AND is_active = true',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        const user = result.rows;
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        // Mise à jour last_login
        await pool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
            [user.id]
        );

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                role: user.role,
                specialization: user.specialization
            }
        });
    } catch (error) {
        console.error('Erreur login:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Inscription médecin
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, fullName, phone, specialization, licenseNumber} = req.body;

        // Vérifier si l'email existe déjà
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Cet email est déjà utilisé' });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const result = await pool.query(
            `INSERT INTO users (email, password_hash, full_name, phone, specialization, 
            license_number)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, full_name, role`,
            [email, passwordHash, fullName, phone, specialization, licenseNumber]
        );

        const user = result.rows;

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({ token, user });
    } catch (error) {
        console.error('Erreur registration:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================
// ROUTES - RENDEZ-VOUS
// ==================

// Obtenir tous les rendez-vous (Dashboard Médecin)
app.get('/api/appointments', authenticateToken, async (req, res) => {
    try {
        const { status, date, doctorId } = req.query;

        // Si doctorId est fourni, l'utiliser. Sinon, utiliser l'ID de l'utilisateur authentifié.
        // NOTE: Un contrôle d'autorisation RBAC strict devrait être ajouté ici pour vérifier
        // que req.user.id == doctorId, sauf si req.user.role == 'admin'.
        const targetDoctorId = doctorId || req.user.id; 

        let query = 'SELECT * FROM v_appointments_full WHERE 1=1';
        const params = [];
        let paramCount = 1;

        if (status) {
            query += ` AND status = $${paramCount}`;
            params.push(status);
            paramCount++;
        }

        if (date) {
            query += ` AND appointment_date = $${paramCount}`;
            params.push(date);
            paramCount++;
        }

        // Toujours filtrer par docteur pour l'interface médecin
        query += ` AND doctor_id = $${paramCount}`;
        params.push(targetDoctorId);
        paramCount++;
        
        query += ' ORDER BY appointment_date DESC, appointment_time DESC';

        const result = await pool.query(query, params);
        res.json(result.rows);

    } catch (error) {
        console.error('Erreur récupération rendez-vous:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Créer un rendez-vous (via l'AI Chatbot)
app.post('/api/appointments', async (req, res) => {
    try {
        const {
            patientName, patientPhone, patientEmail,
            appointmentDate, appointmentTime, reason, notes,
            doctorId, conversationId
        } = req.body;

        // 1. Vérifier si le patient existe, sinon le créer
        let patientResult = await pool.query(
            'SELECT id FROM patients WHERE phone = $1',
            [patientPhone]
        );
        
        let patientId;
        if (patientResult.rows.length === 0) {
            // Créer nouveau patient
            const newPatient = await pool.query(
                `INSERT INTO patients (full_name, phone, email)
                VALUES ($1, $2, $3) RETURNING id`,
                [patientName, patientPhone, patientEmail]
            );
            patientId = newPatient.rows.id;
        } else {
            patientId = patientResult.rows.id;
        }

        // 2. Créer le rendez-vous
        const appointmentResult = await pool.query(
            `INSERT INTO appointments
            (patient_id, doctor_id, appointment_date, appointment_time, reason, notes,
            ai_conversation_id, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'ai')
            RETURNING *`,
           
        );

        // 3. Mettre à jour la conversation AI (optionnel, selon le schéma complet)
if (conversationId) {
  await pool.query(
    `UPDATE ai_conversations 
     SET appointment_created = true, appointment_id = $1 
     WHERE id = $2`,
    [appointmentResult.rows[0].id, conversationId] // ✅ correction ici
  );
}

res.status(201).json({
  success: true,
  appointment: appointmentResult.rows
});


    } catch (error) {
        console.error('Erreur création rendez-vous:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Mettre à jour le statut d'un rendez-vous (Médecin)
app.patch('/api/appointments/:id/status', authenticateToken, async (req, res) => {
    try {
        const {id} = req.params;
        const { status, cancellationReason } = req.body;
        
        // Sécurité: Vérifier que l'utilisateur authentifié est le docteur du RDV (omission pour brièveté, mais critique en prod)
        //...

        let query = 'UPDATE appointments SET status = $1, updated_at = CURRENT_TIMESTAMP';
        const params = [status, id];

        if (status === 'cancelled' && cancellationReason) {
            query += ', cancellation_reason = $3, cancelled_at = CURRENT_TIMESTAMP, cancelled_by = $4';
            params.push(cancellationReason, 'doctor');
        }

        if (status === 'completed') {
            query += ', completed_at = CURRENT_TIMESTAMP';
        }

        // NOTE: $2 est l'id du RDV (position 2 dans le tableau params)
        query += ` WHERE id = $${params.length + 1 - 1} RETURNING *`;
        
        const result = await pool.query(query, params);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Rendez-vous non trouvé' });
        }

        res.json(result.rows);

    } catch (error) {
        console.error('Erreur mise à jour rendez-vous:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});


// ==================
// ROUTES - AI CONVERSATION
// ==================

// Démarrer une nouvelle conversation (Patient)
app.post('/api/ai/conversation/start', async (req, res) => {
    try {
        const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        const result = await pool.query(
            `INSERT INTO ai_conversations (session_id, status, user_agent, ip_address)
            VALUES ($1, 'active', $2, $3) RETURNING id, session_id`,
            [sessionId, req.headers['user-agent'], req.ip]
        );

        const conversation = result.rows;
        
        // Ajouter le message de bienvenue (initial greeting)
        const greetingMessage = generateAIResponse(null, 'greeting');

        await pool.query(
            `INSERT INTO ai_messages (conversation_id, sender, message_text, intent)
            VALUES ($1, 'ai', $2, 'greeting')`,
            [conversation.id, greetingMessage]
        );

        res.json({
            conversationId: conversation.id,
            sessionId: conversation.session_id,
            message: greetingMessage
        });
    } catch (error) {
        console.error('Erreur démarrage conversation:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Envoyer un message à l'AI (Patient)
app.post('/api/ai/conversation/message', async (req, res) => {
    try {
        const { conversationId, message, conversationState } = req.body; // conversationState doit être envoyé par le frontend
        
        if (!conversationId ||!message) {
            return res.status(400).json({ error: 'conversationId et message requis' });
        }

        // Analyser l'intention (plus pour le futur ou l'annulation)
        const { intent, confidence } = await analyzelntent(message);

        // 1. Sauvegarder le message utilisateur
        await pool.query(
            `INSERT INTO ai_messages (conversation_id, sender, message_text, intent, 
            confidence_score)
            VALUES ($1, 'patient', $2, $3, $4)`,
            [conversationId, message, intent, confidence]
        );
        
        // 2. Mettre à jour le compteur de messages
        await pool.query(
            'UPDATE ai_conversations SET total_messages = total_messages + 1 WHERE id = $1',
            [conversationId]
        );
        
        // 3. Générer la réponse AI (basée sur l'état de conversation reçu du frontend)
        const aiResponse = await generateAIResponse(message, conversationState);

        // 4. Sauvegarder la réponse AI
        await pool.query(
            `INSERT INTO ai_messages (conversation_id, sender, message_text, intent)
            VALUES ($1, 'ai', $2, 'response')`, // Utilisation de 'response' car l'intention est gérée par le frontend
           
        );

        res.json({
            response: aiResponse,
            intent,
            confidence
        });
    } catch (error) {
        console.error('Erreur traitement message:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================
// ROUTES - STATISTIQUES
// ==================

// Obtenir les statistiques du dashboard (CORRIGÉ)
app.get('/api/statistics/dashboard', authenticateToken, async (req, res) => {
    try {
        const { doctorId } = req.query;
        // Utiliser l'ID du docteur fourni ou celui de l'utilisateur authentifié
        const targetDoctorId = doctorId || req.user.id; 

        // Rendez-vous aujourd'hui
        const todayStats = await pool.query(
            `SELECT COUNT(*) as count FROM appointments
            WHERE appointment_date = CURRENT_DATE
            AND doctor_id = $1`,
           
        );
        
        // Rendez-vous en attente
        const pendingStats = await pool.query(
            `SELECT COUNT(*) as count FROM appointments
            WHERE status = 'pending'
            AND doctor_id = $1`,
           
        );
        
        // Rendez-vous complétés (mois en cours)
        const completedStats = await pool.query(
            `SELECT COUNT(*) as count FROM appointments
            WHERE status = 'completed'
            AND DATE_TRUNC('month', appointment_date) = DATE_TRUNC('month', CURRENT_DATE)
            AND doctor_id = $1`,
           
        );
        
        // Taux d'annulation (mois en cours)
        const cancellationRate = await pool.query(
            `SELECT
            COUNT(CASE WHEN status = 'cancelled' THEN 1 END)::FLOAT / 
            NULLIF(COUNT(*), 0) * 100 as rate
            FROM appointments
            WHERE DATE_TRUNC('month', appointment_date) = DATE_TRUNC('month', CURRENT_DATE)
            AND doctor_id = $1`,
           
        );

        // Statistiques AI (CORRIGÉ: jointure sur appointments pour filtrer par doctor_id)
        const aiStats = await pool.query(
            `SELECT
            COUNT(ac.*) as total_conversations,
            COUNT(CASE WHEN ac.appointment_created = true THEN 1 END) as successful,
            COUNT(CASE WHEN a.status = 'completed' AND ac.appointment_created = true THEN 1 END) as completed_appointments_from_ai
            FROM ai_conversations ac
            LEFT JOIN appointments a ON ac.appointment_id = a.id
            WHERE DATE_TRUNC('month', ac.started_at) = DATE_TRUNC('month', CURRENT_DATE)
            AND a.doctor_id = $1`, // FILTRE CRITIQUE APPLIQUÉ
           
        );
        
        const totalConversations = parseInt(aiStats.rows.total_conversations || 0);
        const successfulConversations = parseInt(aiStats.rows.successful || 0);

        res.json({
            today: parseInt(todayStats.rows.count || 0),
            pending: parseInt(pendingStats.rows.count || 0),
            completed: parseInt(completedStats.rows.count || 0),
            cancellationRate: parseFloat(cancellationRate.rows.rate || 0).toFixed(2),
            aiConversations: totalConversations,
            aiSuccessRate: totalConversations > 0
               ? ((successfulConversations / totalConversations) * 100).toFixed(2)
                : 0,
            aiCompletedAppointments: parseInt(aiStats.rows.completed_appointments_from_ai || 0)
        });

    } catch (error) {
        console.error('Erreur statistiques dashboard:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================
// ROUTES - DISPONIBILITÉS
// ==================

// Obtenir les créneaux disponibles
app.get('/api/availability/slots', async (req, res) => {
    try {
        const { date, doctorId } = req.query;
        if (!date) {
            return res.status(400).json({ error: 'Date requise' });
        }

        // Si aucun doctorId fourni, on prend un ID par défaut (ex : 1)
        const targetDoctorId = doctorId || 1;
        const dayOfWeek = new Date(date).getDay(); // 0 = Dimanche, 6 = Samedi

        // 1️⃣ Récupérer les disponibilités du jour
        const availability = await pool.query(
            `SELECT * FROM doctor_availability
             WHERE doctor_id = $1 AND day_of_week = $2 AND is_available = true`,
            [targetDoctorId, dayOfWeek]
        );

        if (availability.rows.length === 0) {
            return res.json({ slots: [] });
        }

        // 2️⃣ Récupérer les rendez-vous existants (excluant annulés / no_show)
        const existingAppointments = await pool.query(
            `SELECT appointment_time FROM appointments
             WHERE doctor_id = $1 AND appointment_date = $2
             AND status NOT IN ('cancelled', 'no_show')`,
            [targetDoctorId, date]
        );
        const bookedTimes = new Set(existingAppointments.rows.map(r => r.appointment_time));

        // 3️⃣ Générer les créneaux disponibles
        const slots = [];

        for (const period of availability.rows) {
            let currentTime = period.start_time;
            const endTime = period.end_time;

            while (currentTime < endTime) {
                if (!bookedTimes.has(currentTime)) {
                    slots.push({
                        time: currentTime.substring(0, 5), // Format HH:MM
                        available: true
                    });
                }

                // Ajouter la durée du créneau
                const [hours, minutes, seconds] = currentTime.split(':');
                const slotDate = new Date();
                slotDate.setHours(parseInt(hours));
                slotDate.setMinutes(parseInt(minutes) + (period.slot_duration || 30)); // par défaut 30 min
                slotDate.setSeconds(parseInt(seconds || 0));

                // Formater pour la prochaine itération (HH:MM:SS)
                currentTime = `${String(slotDate.getHours()).padStart(2, '0')}:${String(slotDate.getMinutes()).padStart(2, '0')}:${String(slotDate.getSeconds()).padStart(2, '0')}`;

                // Sécurité : éviter boucle infinie
                if (!period.slot_duration || period.slot_duration <= 0) break;
            }
        }

        // ✅ Retour final
        res.json({ slots });

    } catch (error) {
        console.error('❌ Erreur récupération créneaux:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================
// DÉMARRAGE DU SERVEUR
// ==================
app.listen(PORT, () => {
    console.log(`✅ Serveur AI Réceptionniste démarré sur le port ${PORT}`);
    console.log(`📡 API disponible à: http://localhost:${PORT}/api`);
});

module.exports = app;
