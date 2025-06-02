"""
Flask routes for push notification API endpoints
"""
from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user
from calorie_tracker.models import PushSubscription, db
from calorie_tracker import config
import os
import json

# Create a blueprint for push notification routes
push_notification_bp = Blueprint('push_notification', __name__)

@push_notification_bp.route('/api/vapid-public-key', methods=['GET'])
@login_required
def vapid_public_key():
    """Return the VAPID public key for push subscription"""
    # Get the VAPID public key from environment variable or config
    public_key = config.VAPID_PUBLIC_KEY
    
    if not public_key:
        return jsonify({'error': 'VAPID public key not configured'}), 500
    
    return jsonify({'publicKey': public_key})

@push_notification_bp.route('/api/push-subscription', methods=['POST'])
@login_required
def save_subscription():
    """Save a push subscription for the current user"""
    data = request.json
    
    if not data or 'subscription' not in data:
        return jsonify({'error': 'Invalid request data'}), 400
    
    subscription = data['subscription']
    user_agent = data.get('userAgent', request.user_agent.string)
    
    if not subscription or 'endpoint' not in subscription or 'keys' not in subscription:
        return jsonify({'error': 'Invalid subscription data'}), 400
    
    try:
        # Check if subscription already exists
        existing_sub = PushSubscription.query.filter_by(
            user_id=current_user.id,
            endpoint=subscription['endpoint']
        ).first()
        
        if existing_sub:
            # Update existing subscription
            existing_sub.p256dh = subscription['keys']['p256dh']
            existing_sub.auth = subscription['keys']['auth']
            existing_sub.user_agent = user_agent
        else:
            # Create new subscription
            new_sub = PushSubscription(
                user_id=current_user.id,
                endpoint=subscription['endpoint'],
                p256dh=subscription['keys']['p256dh'],
                auth=subscription['keys']['auth'],
                user_agent=user_agent
            )
            db.session.add(new_sub)
        
        db.session.commit()
        return jsonify({'success': True}), 201
    
    except Exception as e:
        current_app.logger.error(f"Error saving push subscription: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to save subscription'}), 500

@push_notification_bp.route('/api/push-subscription', methods=['DELETE'])
@login_required
def delete_subscription():
    """Delete a push subscription for the current user"""
    data = request.json
    
    if not data or 'subscription' not in data:
        return jsonify({'error': 'Invalid request data'}), 400
    
    subscription = data['subscription']
    
    if not subscription or 'endpoint' not in subscription:
        return jsonify({'error': 'Invalid subscription data'}), 400
    
    try:
        # Find and delete the subscription
        sub = PushSubscription.query.filter_by(
            user_id=current_user.id,
            endpoint=subscription['endpoint']
        ).first()
        
        if sub:
            db.session.delete(sub)
            db.session.commit()
        
        return jsonify({'success': True})
    
    except Exception as e:
        current_app.logger.error(f"Error deleting push subscription: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete subscription'}), 500

@push_notification_bp.route('/api/notification-preferences', methods=['POST'])
@login_required
def update_notification_preferences():
    """Update notification preferences for the current user"""
    data = request.json
    
    try:
        # Update user preferences
        current_user.notifications_enabled = data.get('enabled', False)
        current_user.notify_meal_reminder = data.get('meal_reminder', True)
        current_user.notify_goal_achievement = data.get('goal_achievement', True)
        current_user.notify_updates = data.get('updates', True)
        
        if 'reminder_time' in data:
            current_user.reminder_time = data['reminder_time']
        
        db.session.commit()
        return jsonify({'success': True})
    
    except Exception as e:
        current_app.logger.error(f"Error updating notification preferences: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update preferences'}), 500
