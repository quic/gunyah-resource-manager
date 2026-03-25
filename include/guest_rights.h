// Automatically generated. Do not modify.
//
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Hypervisor Cap Rights

#define CAP_RIGHTS_ADDRSPACE_ATTACH	      (cap_rights_t)0x1U
#define CAP_RIGHTS_ADDRSPACE_MAP	      (cap_rights_t)0x2U
#define CAP_RIGHTS_ADDRSPACE_LOOKUP	      (cap_rights_t)0x4U
#define CAP_RIGHTS_ADDRSPACE_CONFIGURE_RANGE  (cap_rights_t)0x8U
#define CAP_RIGHTS_ADDRSPACE_MAP_PROTECTED    (cap_rights_t)0x10U
#define CAP_RIGHTS_ADDRSPACE_MODIFY_PROTECTED (cap_rights_t)0x20U
#define CAP_RIGHTS_ADDRSPACE_ADD_INFO	      (cap_rights_t)0x40U
#define CAP_RIGHTS_ADDRSPACE_OBJECT_ACTIVATE  (cap_rights_t)0x80000000U
#define CAP_RIGHTS_ADDRSPACE_ALL	      (cap_rights_t)0x8000007fU

#define CAP_RIGHTS_CSPACE_CAP_CREATE	  (cap_rights_t)0x1U
#define CAP_RIGHTS_CSPACE_CAP_DELETE	  (cap_rights_t)0x2U
#define CAP_RIGHTS_CSPACE_CAP_COPY	  (cap_rights_t)0x4U
#define CAP_RIGHTS_CSPACE_ATTACH	  (cap_rights_t)0x8U
#define CAP_RIGHTS_CSPACE_CAP_REVOKE	  (cap_rights_t)0x10U
#define CAP_RIGHTS_CSPACE_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_CSPACE_ALL		  (cap_rights_t)0x8000001fU

#define CAP_RIGHTS_DOORBELL_SEND	    (cap_rights_t)0x1U
#define CAP_RIGHTS_DOORBELL_RECEIVE	    (cap_rights_t)0x2U
#define CAP_RIGHTS_DOORBELL_BIND	    (cap_rights_t)0x4U
#define CAP_RIGHTS_DOORBELL_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_DOORBELL_ALL		    (cap_rights_t)0x80000007U

#define CAP_RIGHTS_GENERIC_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_GENERIC_ALL		   (cap_rights_t)0x80000000U

#define CAP_RIGHTS_GICV3_ITS_BIND_DEVICE     (cap_rights_t)0x1U
#define CAP_RIGHTS_GICV3_ITS_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_GICV3_ITS_ALL	     (cap_rights_t)0x80000001U

#define CAP_RIGHTS_HWIRQ_BIND_VIC	 (cap_rights_t)0x2U
#define CAP_RIGHTS_HWIRQ_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_HWIRQ_ALL		 (cap_rights_t)0x80000002U

#define CAP_RIGHTS_MEMEXTENT_MAP	     (cap_rights_t)0x1U
#define CAP_RIGHTS_MEMEXTENT_DERIVE	     (cap_rights_t)0x2U
#define CAP_RIGHTS_MEMEXTENT_ATTACH	     (cap_rights_t)0x4U
#define CAP_RIGHTS_MEMEXTENT_LOOKUP	     (cap_rights_t)0x8U
#define CAP_RIGHTS_MEMEXTENT_DONATE	     (cap_rights_t)0x10U
#define CAP_RIGHTS_MEMEXTENT_PROTECTED_HOST  (cap_rights_t)0x20U
#define CAP_RIGHTS_MEMEXTENT_PROTECTED_GUEST (cap_rights_t)0x40U
#define CAP_RIGHTS_MEMEXTENT_MAP_PRIVATE     (cap_rights_t)0x80U
#define CAP_RIGHTS_MEMEXTENT_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_MEMEXTENT_ALL	     (cap_rights_t)0x800000ffU

#define CAP_RIGHTS_MSGQUEUE_SEND	    (cap_rights_t)0x1U
#define CAP_RIGHTS_MSGQUEUE_RECEIVE	    (cap_rights_t)0x2U
#define CAP_RIGHTS_MSGQUEUE_BIND_SEND	    (cap_rights_t)0x4U
#define CAP_RIGHTS_MSGQUEUE_BIND_RECEIVE    (cap_rights_t)0x8U
#define CAP_RIGHTS_MSGQUEUE_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_MSGQUEUE_ALL		    (cap_rights_t)0x8000000fU

#define CAP_RIGHTS_PARTITION_OBJECT_CREATE   (cap_rights_t)0x1U
#define CAP_RIGHTS_PARTITION_DONATE	     (cap_rights_t)0x2U
#define CAP_RIGHTS_PARTITION_QUERY	     (cap_rights_t)0x4U
#define CAP_RIGHTS_PARTITION_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_PARTITION_ALL	     (cap_rights_t)0x80000007U

#define CAP_RIGHTS_PCI_FUNCTION_PASSTHROUGH	(cap_rights_t)0x1U
#define CAP_RIGHTS_PCI_FUNCTION_ATTACH		(cap_rights_t)0x2U
#define CAP_RIGHTS_PCI_FUNCTION_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_PCI_FUNCTION_ALL		(cap_rights_t)0x80000003U

#define CAP_RIGHTS_PCI_HOST_CREATE_FUNCTION (cap_rights_t)0x1U
#define CAP_RIGHTS_PCI_HOST_SET_LOCKDOWN    (cap_rights_t)0x2U
#define CAP_RIGHTS_PCI_HOST_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_PCI_HOST_ALL		    (cap_rights_t)0x80000003U

#define CAP_RIGHTS_POWER_SYSTEM_SUSPEND	 (cap_rights_t)0x1U
#define CAP_RIGHTS_POWER_CPU_SUSPEND	 (cap_rights_t)0x2U
#define CAP_RIGHTS_POWER_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_POWER_ALL		 (cap_rights_t)0x80000003U

#define CAP_RIGHTS_SMMUV3_CONFIGURE	  (cap_rights_t)0x1U
#define CAP_RIGHTS_SMMUV3_MANAGE_STREAMS  (cap_rights_t)0x2U
#define CAP_RIGHTS_SMMUV3_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_SMMUV3_ALL		  (cap_rights_t)0x80000003U

#define CAP_RIGHTS_THREAD_POWER		  (cap_rights_t)0x1U
#define CAP_RIGHTS_THREAD_AFFINITY	  (cap_rights_t)0x2U
#define CAP_RIGHTS_THREAD_PRIORITY	  (cap_rights_t)0x4U
#define CAP_RIGHTS_THREAD_TIMESLICE	  (cap_rights_t)0x8U
#define CAP_RIGHTS_THREAD_YIELD_TO	  (cap_rights_t)0x10U
#define CAP_RIGHTS_THREAD_BIND_VIRQ	  (cap_rights_t)0x20U
#define CAP_RIGHTS_THREAD_STATE		  (cap_rights_t)0x40U
#define CAP_RIGHTS_THREAD_LIFECYCLE	  (cap_rights_t)0x80U
#define CAP_RIGHTS_THREAD_WRITE_CONTEXT	  (cap_rights_t)0x100U
#define CAP_RIGHTS_THREAD_DISABLE	  (cap_rights_t)0x200U
#define CAP_RIGHTS_THREAD_BIND_LOCAL_VIRQ (cap_rights_t)0x400U
#define CAP_RIGHTS_THREAD_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_THREAD_ALL		  (cap_rights_t)0x800007ffU

#define CAP_RIGHTS_VGIC_ITS_BIND_VIC	     (cap_rights_t)0x1U
#define CAP_RIGHTS_VGIC_ITS_ATTACH_ADDRSPACE (cap_rights_t)0x2U
#define CAP_RIGHTS_VGIC_ITS_BIND_DEVICES     (cap_rights_t)0x4U
#define CAP_RIGHTS_VGIC_ITS_UNBIND_DEVICES   (cap_rights_t)0x8U
#define CAP_RIGHTS_VGIC_ITS_OBJECT_ACTIVATE  (cap_rights_t)0x80000000U
#define CAP_RIGHTS_VGIC_ITS_ALL		     (cap_rights_t)0x8000000fU

#define CAP_RIGHTS_VIC_BIND_SOURCE     (cap_rights_t)0x1U
#define CAP_RIGHTS_VIC_ATTACH_VCPU     (cap_rights_t)0x2U
#define CAP_RIGHTS_VIC_ATTACH_VDEVICE  (cap_rights_t)0x4U
#define CAP_RIGHTS_VIC_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_VIC_ALL	       (cap_rights_t)0x80000007U

#define CAP_RIGHTS_VIRTIO_BACKEND_BIND_VIRQ		  (cap_rights_t)0x1U
#define CAP_RIGHTS_VIRTIO_BACKEND_BIND_MMIO_FRONTEND_VIRQ (cap_rights_t)0x2U
#define CAP_RIGHTS_VIRTIO_BACKEND_ASSERT_VIRQ		  (cap_rights_t)0x4U
#define CAP_RIGHTS_VIRTIO_BACKEND_CONFIG		  (cap_rights_t)0x8U
#define CAP_RIGHTS_VIRTIO_BACKEND_BIND_VPCI		  (cap_rights_t)0x10U
#define CAP_RIGHTS_VIRTIO_BACKEND_OBJECT_ACTIVATE	  (cap_rights_t)0x80000000U
#define CAP_RIGHTS_VIRTIO_BACKEND_ALL			  (cap_rights_t)0x8000001fU

#define CAP_RIGHTS_VIRTIO_IOMMU_BIND_VPCI	(cap_rights_t)0x1U
#define CAP_RIGHTS_VIRTIO_IOMMU_MANAGE_STREAMS	(cap_rights_t)0x2U
#define CAP_RIGHTS_VIRTIO_IOMMU_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_VIRTIO_IOMMU_ALL		(cap_rights_t)0x80000003U

#define CAP_RIGHTS_VPCI_ATTACH		(cap_rights_t)0x1U
#define CAP_RIGHTS_VPCI_BIND		(cap_rights_t)0x2U
#define CAP_RIGHTS_VPCI_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_VPCI_ALL		(cap_rights_t)0x80000003U

#define CAP_RIGHTS_VPM_GROUP_ATTACH_VCPU     (cap_rights_t)0x1U
#define CAP_RIGHTS_VPM_GROUP_BIND_VIRQ	     (cap_rights_t)0x2U
#define CAP_RIGHTS_VPM_GROUP_QUERY	     (cap_rights_t)0x4U
#define CAP_RIGHTS_VPM_GROUP_WAKEUP	     (cap_rights_t)0x8U
#define CAP_RIGHTS_VPM_GROUP_BIND_POWER	     (cap_rights_t)0x10U
#define CAP_RIGHTS_VPM_GROUP_SET_THRESHOLD   (cap_rights_t)0x20U
#define CAP_RIGHTS_VPM_GROUP_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_VPM_GROUP_ALL	     (cap_rights_t)0x8000003fU

#define CAP_RIGHTS_VRTC_CONFIGURE	 (cap_rights_t)0x1U
#define CAP_RIGHTS_VRTC_ATTACH_ADDRSPACE (cap_rights_t)0x2U
#define CAP_RIGHTS_VRTC_SET_TIME_BASE	 (cap_rights_t)0x4U
#define CAP_RIGHTS_VRTC_OBJECT_ACTIVATE	 (cap_rights_t)0x80000000U
#define CAP_RIGHTS_VRTC_ALL		 (cap_rights_t)0x80000007U

#define CAP_RIGHTS_VSMMUV2_MANAGE_STREAMS   (cap_rights_t)0x1U
#define CAP_RIGHTS_VSMMUV2_ATTACH_ADDRSPACE (cap_rights_t)0x2U
#define CAP_RIGHTS_VSMMUV2_OBJECT_ACTIVATE  (cap_rights_t)0x80000000U
#define CAP_RIGHTS_VSMMUV2_ALL		    (cap_rights_t)0x80000003U

#define CAP_RIGHTS_WATCHDOG_ATTACH_VCPU	    (cap_rights_t)0x1U
#define CAP_RIGHTS_WATCHDOG_BIND_VIRQ	    (cap_rights_t)0x2U
#define CAP_RIGHTS_WATCHDOG_MANAGE	    (cap_rights_t)0x4U
#define CAP_RIGHTS_WATCHDOG_OBJECT_ACTIVATE (cap_rights_t)0x80000000U
#define CAP_RIGHTS_WATCHDOG_ALL		    (cap_rights_t)0x80000007U
