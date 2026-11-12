import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { maintenanceLimiter } from '../middleware/rateLimit.js';
import {
  getAllRequests, getRequest, createRequest, updateRequest, deleteRequest
} from '../controllers/maintenanceController.js';

const router = Router();

// DoS fix — throttles every maintenance endpoint, including the public list
// the attacker's page floods.
router.use(maintenanceLimiter);

// CSRF fix is applied app-wide in app.js: GETs stay exempt, the writes now
// require a token the attacker's site can neither read nor guess.
router.get('/', getAllRequests);
router.get('/:id', getRequest);
router.post('/', requireAuth, createRequest);
router.patch('/:id', requireAuth, updateRequest);
router.delete('/:id', requireAuth, deleteRequest);

export default router;